import argparse
import os
from idstools import rule

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
    if "(?P=" in pcre:
        return False

    return True

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
    return [identifier("all", "any"), identifier("all", inp_cat), identifier(proto, "any")]

def compute_group_tuples():
    for proto in SUPPORTED_PROTOCOLS:
        for in_cat in SUPPORTED_IP_CLASSES:
            yield (proto, in_cat)

def get_group_identifiers():
    for tup in compute_group_tuples():
        yield identifier(*tup)

class GroupClassifier():
    def __init__(self):
        self.regexes = {}
        for ident in get_group_identifiers():
            self.regexes[ident] = []

    def add(self, proto, src_ip_class, src_port, dst_ports, regex):
        self.regexes[identifier(proto, src_ip_class, src_port, dst_ports)].append(regex)

    def get_category(self, proto, src_ip_class):
        # Return the category --- with one modification, 
        # that we also add all the sub-categories.
        regexes = self.regexes[identifier(proto, src_ip_class)][:]
        super_regexes_cats = compute_supercategories(proto, src_ip_class)

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
def extract_groups_from(input_file):
    rules = rule.parse_file(input_file)
    groups = GroupClassifier()

    for snort_rule in rules:
        header = snort_rule.header.split(" ")
        if "pcre" not in snort_rule:
            # Don't care about the non regex rules.
            continue
        if not is_valid_pcre(snort_rule.pcre):
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

        # TODO --- Do something about ports, which generally
        # have a wider range...

        groups.add(proto, src_ips_type, src_ports, dst_ports, format_pcre(snort_rule.pcre))

    return groups


def write_groups_to(groups, outfolder):
    if not os.path.exists(outfolder):
        os.mkdir(outfolder)
    for group_id in compute_group_tuples():
        regexes = groups.get_category(*group_id)
        ident = identifier(*group_id).replace("$", "")

        with open(outfolder + "/" + ident, "w") as f:
            f.write("\n".join(regexes))


# This is a script that, given an input Snort rulefile, produces
# a set of N different regex files that each correspond to
# regexes that can only be run on distinct packets.

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file')
    parser.add_argument('output_folder')

    args = parser.parse_args()

    groups = extract_groups_from(args.input_file)
    write_groups_to(groups, args.output_folder)
