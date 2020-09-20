import argparse
import os
from idstools import rule
not_valid = 0

SUPPORTED_PROTOCOLS = ["all", "tcp", "udp", "icmp"]
SUPPORTED_IP_CLASSES = ["any", "$HOME_NET", "$EXTERNAL_NET"]
# These two are mutable and are added to as PCREs from particular
# ports are added
SUPPORTED_INP_PORTS = ["any"]
SUPPORTED_OUT_PORTS = ["any"]

def is_valid_pcre(pcre):
    # The other tooling (pcre2mnrl) imposes various restrictions --- if the
    # pcre isn't valid, it should be skipped.
    # The problem is, I don't want to parse the PCRE, so just put in
    # enough hacks until it works.
    # Broken VAsim tool.
    if "(?P=" in pcre:
        return False
    if "?=" in pcre:
        return False
    # Atomic groups not supported by vasim
    if "(?>" in pcre:
        return False
    # I think this was causing issues with zero-width assertions?
    if "?<!" in pcre:
        return False
    # Possisive quantifiers not supported by vasim
    if "}+" in pcre:
        return False
    # VAsim doesn't support backreferences -- can't find the backreference on the regex with this though.
    if "(.)" in pcre:
        return False
    # Broken vasim tool
    if "?!\\n" in pcre:
        return False
    if "?!" in pcre:
        return False

    # Exclude a particular PCRE in the snort set that doesn't work, but where I can't actually find the part that is broken in VAsim
    if "(^P" in pcre:
        return False
    if "(^Accept:" in pcre:
        return False
    if "(^[^\\r\\n]+?\\r" in pcre:
        return False
    if "(\\x26|$)" in pcre:
        return False
    if "(^P" in pcre:
        return False
    if "(^a\\x3Drtpmap" in pcre:
        return False
    if "(^|&)*?" in pcre:
        return False

    # Back references are unsupported (pcre2mnrl)
    if "\\1" in pcre:
        return False
    if "\\2" in pcre:
        return False
    if "\\5" in pcre:
        return False
    if "\\9" in pcre:
        return False

    # pcre2mnrl doesn't seem to fully support things that match
    # an empty buffer.
    if "/|" in pcre or "|/" in pcre:
        return False

    # My tool failed oon the one that had this for some unknown reason.  It was hard to debug, so I'm omitting it.
    # It wasn't even just this regex, but rather a whole complicated
    # combo of them...
    if "(INSERT|UPDATE)\s*[\s\w]*((mysql\.)?func)" in pcre:
        return False

    # Embedded start anchors not supported in vasim.
    # embedded start anchor means '^' not in a character
    # class.  However, a huge number of PCREs have
    # this character, so we just replace it with \n.
    last_character = None
    index = 0
    chrs = list(pcre)
    for character in chrs:
        if character == "^":
            if last_character == '/' or last_character == "[" or last_character == '(' or last_character == '|' or last_character == '\\':
                pass
            else:
                return False
        if character == "$":
            if chrs[index + 1] == '/' or chrs[index + 1] == ']' or last_character == '[' or last_character == '\\' or last_character == '|' or last_character == '(' or chrs[index + 1] == ')':
                pass
            else:
                return False
        index += 1

        last_character = character

    return "".join(chrs)

def format_pcre(pcre):
    # The PCRE comes wrapped in "'s and sometines is
    # negated --- remove the negation and the "s
    if pcre.startswith("!"):
        pcre = pcre[1:]
    if pcre.startswith('"'):
        pcre = pcre[1:]
    if pcre.endswith('"'):
        pcre = pcre[:-1]
    # remove flags --- some flags arent' liked by vasim, so just
    # get rid of them all --- probably not that important for
    # the concept anyway.
    while not pcre.endswith("/"):
        pcre = pcre[:-1]
    return pcre

# Generate a key for some sequence of things.
def identifier(proto, inp_cat, inp_ports, out_ports):
    return proto + inp_cat + inp_ports + out_ports

# return the identifiers of any supercategories (i.e. any other
# categories that have to be run also)
def compute_supercategories(proto, inp_cat, inp_ports, out_ports):
    # Just takes some elbow grease to write all these down.
    assert False
    protos = [proto, "all"]
    inp_cats = [inp_cat, "any"]
    inp_ports = [inp_ports, SUPPORTED_INP_PORTS[0]]
    out_ports = [out_ports, SUPPORTED_OUT_PORTS[0]]
    return [identifier("all", "any"), identifier("all", inp_cat), identifier(proto, "any")]

def compute_group_tuples():
    for proto in SUPPORTED_PROTOCOLS:
        for in_cat in SUPPORTED_IP_CLASSES:
            for src_prt in SUPPORTED_INP_PORTS:
                for dst_prt in SUPPORTED_OUT_PORTS:
                    yield (proto, in_cat, src_prt, dst_prt)

def get_group_identifiers():
    for tup in compute_group_tuples():
        yield identifier(*tup)

class GroupClassifier():
    def __init__(self, use_supercats):
        self.regexes = {}
        self.use_supercats = use_supercats
        for ident in get_group_identifiers():
            self.regexes[ident] = []

    def add(self, proto, src_ip_class, src_port, dst_ports, regex):
        ident = identifier(proto, src_ip_class, src_port, dst_ports)
        if ident in self.regexes:
            self.regexes[ident].append(regex)
        else:
            if src_port not in SUPPORTED_INP_PORTS:
                SUPPORTED_INP_PORTS.append(src_port)
            if dst_ports not in SUPPORTED_OUT_PORTS:
                SUPPORTED_OUT_PORTS.append(dst_ports)
            self.regexes[ident] = [regex]

    def get_category(self, proto, src_ip_class, src_prt, dst_prt):
        # Return the category --- with one modification, 
        # that we also add all the sub-categories.
        ident = identifier(proto, src_ip_class, src_prt, dst_prt) 
        if not ident in self.regexes:
            return []
        regexes = self.regexes[ident][:]
        if self.use_supercats:
            super_regexes_cats = compute_supercategories(proto, src_ip_class, src_prt, dst_prt)

            for cat in super_regexes_cats:
                regexes += self.regexes[cat][:]

        return regexes

    def __str__(self):
        res = ""
        for ident in get_group_identifiers():
            res += "Ident: " + ident
            res += "Has contents: " + str(self.regexes[ident])
            res += "\n"
        return res

# The aim of this function is to create distinct sets of
# rules, i.e. rules that can never be run in parallel.
# We have 3 main ways of doing this: Protocol, source/dest IP range
# and source/dest ports
# If any one of these is different, then we have a new group :)
# For now we are just lookup at protocol. (tcp, udp, icmp)
# We expect to get more overlap with IP/port nos.
def extract_groups_from(input_file, use_supercats, limit):
    rules = rule.parse_file(input_file)
    groups = GroupClassifier(use_supercats)
    count = 0

    for snort_rule in rules:
        if count > limit:
            break
        header = snort_rule.header.split(" ")
        if "pcre" not in snort_rule:
            # Don't care about the non regex rules.
            continue
        # This function reformats the PCRE
        pcre = is_valid_pcre(snort_rule.pcre)
        if not pcre:
            global not_valid
            not_valid += 1
            # Not a supported PCRE, don't translate
            continue

        if header[1] in SUPPORTED_PROTOCOLS:
            proto = header[1]
        else:
            print("Type " + header[1] + " not recognized")
            proto = "all"

        src_ips = header[2]
        src_ips_type = None
        if src_ips in SUPPORTED_IP_CLASSES:
            src_ips_type = src_ips
        else:
            print ("Unrecognized src IPs type: " + src_ips)
            src_ips_type = "any"

        src_ports = header[3]
        dst_ports = header[6]

        if ":" in src_ports or ":" in dst_ports or "," in src_ports or "," in dst_ports or "[" in src_ports or "[" in dst_ports:
            continue

        # TODO --- Do something about ports, which generally
        # have a wider range...

        groups.add(proto, src_ips_type, src_ports, dst_ports, format_pcre(pcre))
        count += 1

    print("Number of rules omitted due to unsupported features is" + str(not_valid))
    return groups


def write_groups_to(groups, outfolder):
    if not os.path.exists(outfolder):
        os.mkdir(outfolder)
    for group_id in compute_group_tuples():
        regexes = groups.get_category(*group_id)
        ident = identifier(*group_id).replace("$", "")

        if len(regexes) > 0:
            with open(outfolder + "/" + ident, "w") as f:
                f.write("\n".join(regexes))


# This is a script that, given an input Snort rulefile, produces
# a set of N different regex files that each correspond to
# regexes that can only be run on distinct packets.

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-supercat', default=False, action='store_true', dest='supercat')
    parser.add_argument('--limit', default=1000000000, type=int, dest='limit', help='Limit  the number of regexes to N')
    parser.add_argument('input_file')
    parser.add_argument('output_folder')

    args = parser.parse_args()

    groups = extract_groups_from(args.input_file, args.supercat, args.limit)
    write_groups_to(groups, args.output_folder)
