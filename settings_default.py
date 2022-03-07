"""The file includes settings that can't be controlled via CLI arguments"""
# To set up custom settings just copy that file to settings.py (ignored by git)

# Just add column name and list of values to search for in that column.
no_action_needed_checks = {'_DKIM_OK_for_domains': []}
malicious = {'row/source_ip': []}  # list of known malicious IPs
