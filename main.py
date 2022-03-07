from os.path import join, isdir, isfile, exists
from os import listdir, mkdir, system
from email import message_from_binary_file
import gzip
import zipfile
from io import BytesIO
from hashlib import md5
from defusedxml.ElementTree import fromstring
from csv import DictWriter
from mailbox import mbox
from datetime import datetime
import re
import argparse

try:
    from settings import no_action_needed_checks, malicious
except ModuleNotFoundError:
    try:
        from settings_default import no_action_needed_checks, malicious
    except ModuleNotFoundError:
        no_action_needed_checks = {'_DKIM_OK_for_domains': []}
        malicious = {'row/source_ip': []}  # list of known malicious IPs


class BadArguments(Exception):
    pass


def flatten_xml_record(root, prefix, out_dictionary):
    """Recursive procedure to convert an XML tree to a flat dictionary"""
    for ent in root:
        prefix1 = prefix + ent.tag
        if ent.text is not None and ent.text.strip() != '':
            while prefix1 in out_dictionary:
                prefix1 += '_'
            out_dictionary[prefix1] = ent.text.strip()
        flatten_xml_record(ent, prefix1 + '/', out_dictionary)


def extract_from_zip(part):
    xml_files = []
    bin = part.get_payload(decode=True)
    fd = BytesIO(bin)
    zipf = zipfile.ZipFile(fd)
    for name in zipf.namelist():
        data = zipf.open(name).read()
        xml_files.append((name, data))
    return xml_files


def extract_from_gz(part):
    name = part.get_filename().rstrip('.gz').rstrip('.gzip')
    bin = part.get_payload(decode=True)
    data = gzip.decompress(bin)
    return [(name, data)]


def prepend_key_name(flat_record:dict, key, n=1):
    if key in flat_record and '_' * n + key not in flat_record:
        flat_record['_' * n + key] = flat_record.pop(key)


def process_message(msg):
    """Process all archives with XML files, attached to the email message and form rows to be output to CSV file."""
    xml_files = []  # will contain all xml attachments in tuples: (xml_filename, xml_content)
    subject = msg['Subject']

    # unpack all xml attachments from the message
    for part in msg.walk():
        if part.get_content_type() in ['application/zip', 'application/x-zip-compressed']:
            xml_files += extract_from_zip(part)
        elif part.get_content_type() == 'application/gzip':
            xml_files += extract_from_gz(part)
        elif part.get_content_type() == 'application/octet-stream':
            try:
                xml_files += extract_from_gz(part)
            except gzip.BadGzipFile as e:
                if e.args[0] == "Not a gzipped file (b'PK')":
                    try:
                        xml_files += extract_from_zip(part)
                    except Exception as e:
                        print(
                            "Can't decompress file {} of type {}".format(part.get_filename(), part.get_content_type()))
                        continue
                else:
                    print("Can't decompress file {} of type {}".format(part.get_filename(), part.get_content_type()))
                    continue
        elif part.get_content_type() not in ['multipart/mixed', 'multipart/alternative', 'multipart/related', 'text/plain', 'text/html']:
            print(subject, "contains unknown content-type:", part.get_content_type())
            continue
    if len(xml_files) == 0:
        print("No payload found in {}. That may be a failure report, please check it manually".format(subject))
        return

    # extract interesting headers from the message
    comment = set()
    for header_name, header_value in msg.items():
        if header_name == 'Received':
            srv_type = re_header_received_server_type.search(header_value)
            if srv_type:
                comment.add(srv_type.group('srv'))
        elif header_name == 'DKIM-Filter':
            filter = re_header_dkim_filter.search(header_value)
            if filter:
                comment.add(filter.group(1))

    for xml_file in xml_files:
        # Write the XML report to disk
        new_name_full = ""
        if args.out_xml is not None:
            new_name = (md5(xml_file[1]).hexdigest() + '_' + xml_file[0].replace('!', '_'))[:160]
            new_name_full = join(args.out_xml, new_name)
            with open(new_name_full, 'wb') as f:
                f.write(xml_file[1])
            if args.debug:
                print("An XML file been processed is put to:\t{}".format(new_name_full))


        ## Form rows to be added to CSV file (each <record> goes to a single row) #
        # Extract data from report fields that are common for all records in the report
        et = fromstring(xml_file[1].decode())
        org_name = et.find('./report_metadata/org_name').text
        date_begin = datetime.fromtimestamp(int(et.find('./report_metadata/date_range/begin').text))
        date_end = datetime.fromtimestamp(int(et.find('./report_metadata/date_range/end').text))
        if args.strict_time_range and (date_begin < not_before or date_end > not_after) or \
           not args.strict_time_range and (date_begin > not_after or date_end < not_before):
            continue

        et.findall('./policy_published')
        for e_record in et.findall('./record'):
            flat_record = {'__Begin': date_begin, '__End': date_end, '__org_name': org_name,
                           'xml_file_name': new_name_full}
            flatten_xml_record(e_record, '', flat_record)
            flat_record['__Will_Pass'] = (flat_record['row/policy_evaluated/dkim'] == 'pass') or \
                                         (flat_record['row/policy_evaluated/spf']  == 'pass') or \
                                         ('row/policy_evaluated/reason/comment' in flat_record and
                                          flat_record['row/policy_evaluated/reason/comment'] == 'arc=pass' and
                                          org_name == 'google.com')
            flat_record['Comment'] = '\n'.join(comment)

            # Gather all verified DKIM signatures to a single column
            dkim_verified_domains = []
            n = 0
            while 'auth_results/dkim/result' + '_' * n in flat_record:
                if flat_record['auth_results/dkim/result' + '_' * n].lower() == 'pass':
                    dkim_verified_domains.append(flat_record['auth_results/dkim/domain' + '_' * n])
                n += 1
            flat_record['_DKIM_OK_for_domains'] = ', '.join(dkim_verified_domains)

            # Mark some rows as "Malicious", "No action needed" or "Action needed"
            flat_record['__No_action_needed'] = ''
            flat_record['__malicious'] = ''
            for key_name, val in flat_record.items():
                if key_name in malicious and val in malicious[key_name]:
                    flat_record['__malicious'] += "{}:{}\n".format(key_name, val)
            for key_name, val in flat_record.items():
                if key_name in no_action_needed_checks and val in no_action_needed_checks[key_name]:
                    flat_record['__No_action_needed'] += "{}:{}\n".format(key_name, val)
            if flat_record['__malicious'] != '':
                if flat_record['__Will_Pass']:
                    flat_record['__Action_needed'] = 'Malicious'
                else:
                    flat_record['__No_action_needed'] = 'Malicious' + '\n' + flat_record['__No_action_needed']
            # mark false 'quarantine/reject' records, caused by MDaemon bug
            if flat_record['__Will_Pass'] and flat_record['row/policy_evaluated/disposition'] in ['quarantine', 'reject'] and \
               'MDaemon PRO' in flat_record['Comment']:
                mdaemon_version = re.findall('MDaemon PRO v(\d+\.\d+\.\d+)', flat_record['Comment'])[0].split('.')
                if int(mdaemon_version[0]) < 21 or int(mdaemon_version[0]) == 21 and int(mdaemon_version[1]) == 0 and int(mdaemon_version[2]) == 0:
                    flat_record['__No_action_needed'] += "MDaemon PRO aggregate report bug\n"

            # Move some columns to front
            prepend_key_name(flat_record, 'row/policy_evaluated/disposition', 2)
            prepend_key_name(flat_record, 'row/policy_evaluated/dkim')
            prepend_key_name(flat_record, 'row/policy_evaluated/spf')
            prepend_key_name(flat_record, 'identifiers/header_from')

            for key, val in flat_record.items():
                flat_record[key] = str(val).strip('\n')
            rows.append(flat_record)


parser = argparse.ArgumentParser(description="""Parse aggregated DMARC reports and show them in table.
It takes an mbox file or a directory with .eml files as an input. For example you can create a "local folder" in Thunderbird \
and move all your DMARC reports to that folder. Then you can give path to mbox file \
<home folder>/.thunderbird/<thunderbird profile>/Mail/Local Folders/<folder name> to dmarc_analyser in -m parameter. 
Be aware that parsing untrusted data may pose a security risk. Although this program should not contain any known \
vulnerabilities, you may use some compensating measures, for example run it inside an isolated environment.""")
parser.add_argument("-m", "--mbox_path", help="Path to mbox file")
parser.add_argument("-i", "--in_dir", help="Path to directory with .eml files")
parser.add_argument("-s", "--strict_time_range", help="Make sure all listed events happened inside the time range, \
otherwise make sure all the events that happened inside the time range are shown (latter includes events near the \
border of the time range for which is not know if they are inside the range or not)", action="store_true")
parser.add_argument("-b", "--not_before", help="Time range beginning in ISO format, ex: '2021-08-10T09:30'", default='1970-01-01')
parser.add_argument("-e", "--not_after", help="Time range end in ISO format, ex: '2021-08-11'", default='3000-01-01')
parser.add_argument("-o", "--out_csv", help="Output file")
parser.add_argument("-x", "--out_xml", help="Save report XML files into that dir. XML files are not output if the \
parameter is omitted")
parser.add_argument("-l", "--libreoffice", help="Open output file in LibreOffice", action="store_true")
parser.add_argument("-d", "--debug", help="Output info about currently processed report", action="store_true")
args = parser.parse_args()

if args.out_csv is None:
    args.out_csv = "dmarc.csv"
not_before = datetime.fromisoformat(args.not_before)
not_after = datetime.fromisoformat(args.not_after)

rows = []
re_header_received_server_type = re.compile(".*(?P<srv>MDaemon PRO v\d+\.\d+\.\d+).*")
re_header_dkim_filter = re.compile('.*(OpenDKIM Filter v\d+\.\d+\.\d+).*')

if args.out_xml is not None:
    if exists(args.out_xml) and not isdir(args.out_xml):
        print("Can't create", args.out_xml)
        exit()
    if not exists(args.out_xml):
        mkdir(args.out_xml)


# Actual processing
n_processed = 0
if args.in_dir is not None:
    for f_name in listdir(args.in_dir):
        full_f_name = join(args.in_dir, f_name)
        if full_f_name == args.out_csv or args.out_xml is not None and full_f_name == args.out_xml.rstrip('/'): continue
        if not f_name.endswith('.eml'):
            print("Skipping", f_name)
            continue
        if args.debug:
            print("Processing eml:\t{}".format(f_name))
        elif n_processed % 100 == 0:
            print("Processed emails:\t{}\r".format(n_processed), end='')
        with open(full_f_name, 'rb') as f:
            msg = message_from_binary_file(f)
            process_message(msg)
        n_processed += 1
if args.mbox_path is not None:
    for msg in mbox(args.mbox_path, create=False):
        if args.debug:
            print("Processing eml:\t{}".format(msg['Subject']))
        elif n_processed % 100 == 0:
            print("Processed emails:\t{}\r".format(n_processed), end='')
        process_message(msg)
        n_processed += 1
else:
    parser.error("You should set at least one source: either Mbox file or directory with .eml files")


# Export to CSV
field_names = set()
for record in rows:
    field_names.update(record.keys())

field_names = list(field_names)
field_names.sort()
with open(args.out_csv, 'w', newline='') as csv_f:
    writer = DictWriter(csv_f, fieldnames=field_names)
    writer.writeheader()
    writer.writerows(rows)

if args.libreoffice:
    system('libreoffice {}&'.format(args.out_csv))
