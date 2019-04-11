""" DNS WRITE """




DNSPATH = 'master'
cn = "divecky.com"
validation_data = [[u'a3k34_87XB13BwGQKk6yLpbMBgy451m-Sa32ZcloyMw', '_acme-challenge.adivecky.com'], [u'9SvLl7qboD6d6cPuxHG7Va5jPt_MsX_BIRI7NgoAF9g', '_acme-challenge.adivecky.com']]

#Main functions
def dns_apply_challenge(cn, validation_data):
    if dns_challenge_in_file(cn):
        dns_remove_challenge(cn)
    dns_write_to_file("divecky.com", validation_data)

def dns_remove_challenge(cn):
    with open(DNSPATH + "/" + cn, "r+") as f:
        d = f.readlines()
        f.seek(0)
        for i in d:
            if "_acme-challenge" not in i:
                f.write(i)
        f.truncate()
    if dns_challenge_in_file(cn):
        print "Something is wrong, cannot remove challenge"
        return False

#Subfunctions
def dns_challenge_in_file(cn):
    list = []
    for line in open(DNSPATH + "/" + cn, "r"):
        if "_acme-challenge" in line:
            list.append(line)
    if list:
        return True
    else:
        return False


def dns_write_to_file(cn, validation_data):
    dns_recs = []
    for data in validation_data:
        dns_recs.append("%s\t300\tIN\tTXT\t%s\n" % (data[1], data[0]))
    dnsfile = open(DNSPATH + "/" + cn, "a+")
    for dns_rec in dns_recs:
        dnsfile.write(dns_rec)
    dnsfile.close()
    if dns_challenge_in_file(cn):
        return True
    else:
        print "Unable to write challenge"
        return False

dns_apply_challenge(cn, validation_data)
#dns_remove_challenge(cn)
