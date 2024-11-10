#! /usr/bin/env python3

import json
import shutil
import sys
import tarfile
import tempfile
import os
import requests


def unzip_tar_gz(archive_path):
    """
    Extracts a tar.gz archive to a temporary directory and returns the path to the directory.

    :param archive_path: Path to the tar.gz archive
    :return: Path to the temporary directory where the archive is extracted
    """
    temp_dir = tempfile.mkdtemp()
    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(path=temp_dir, filter="tar")
    return temp_dir


def read_adlist(temp_dir):
    """
    Reads the adlist.json file from the temp directory, filter out the disabled ones and only returns the address and comment fields.

    :param temp_dir: Path to the temporary directory where the archive is extracted
    :return: A list of dictionary with address and comment fields
    """
    adlist_path = os.path.join(temp_dir, "adlist.json")
    with open(adlist_path) as f:
        adlist = json.load(f)
    return [
        {"address": e["address"], "comment": e["comment"]}
        for e in adlist
        if e["enabled"]
    ]


def read_whitelist_exact(temp_dir):
    """
    Reads the whitelist.exact.json file from the temp directory, filter out the disabled ones and only returns the domain and comment fields.

    :param temp_dir: Path to the temporary directory where the archive is extracted
    :return: A list of dictionary with domain and comment fields
    """
    whitelist_path = os.path.join(temp_dir, "whitelist.exact.json")
    with open(whitelist_path) as f:
        whitelist = json.load(f)
    return [
        {"domain": e["domain"], "comment": e["comment"]}
        for e in whitelist
        if e["enabled"] == 1
    ]


def read_blacklist_exact(temp_dir):
    """
    Reads the blacklist.exact.json file from the temp directory, filter out the disabled ones and only returns the domain and comment fields.

    :param temp_dir: Path to the temporary directory where the archive is extracted
    :return: A list of dictionary with domain and comment fields
    """
    blacklist_path = os.path.join(temp_dir, "blacklist.exact.json")
    with open(blacklist_path) as f:
        blacklist = json.load(f)
    return [
        {"domain": e["domain"], "comment": e["comment"]}
        for e in blacklist
        if e["enabled"] == 1
    ]


def read_whitelist_regex(temp_dir):
    """
    Reads the whitelist.regex.json file from the temp directory, filter out the disabled ones and only returns the domain and comment fields.

    :param temp_dir: Path to the temporary directory where the archive is extracted
    :return: A list of dictionary with domain and comment fields
    """
    whitelist_path = os.path.join(temp_dir, "whitelist.regex.json")
    with open(whitelist_path) as f:
        whitelist = json.load(f)
    return [
        {"domain": e["domain"], "comment": e["comment"]}
        for e in whitelist
        if e["enabled"] == 1
    ]


def read_blacklist_regex(temp_dir):
    """
    Reads the blacklist.regex.json file from the temp directory, filter out the disabled ones and only returns the domain and comment fields.

    :param temp_dir: Path to the temporary directory where the archive is extracted
    :return: A list of dictionary with domain and comment fields
    """
    blacklist_path = os.path.join(temp_dir, "blacklist.regex.json")
    with open(blacklist_path) as f:
        blacklist = json.load(f)
    return [
        {"domain": e["domain"], "comment": e["comment"]}
        for e in blacklist
        if e["enabled"] == 1
    ]


def test_url(url):
    """
    Tests if a given URL works by replacing \\/ with /.
    :param url: URL to test
    :return: True if the URL works, False otherwise
    """
    new_url = url.replace("\\/", "/")
    try:
        response = requests.head(new_url)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def filter_working_adlist(adlist):
    """
    Takes a list from read_adlist output, check each address using the test_url funciton, and only return the element with a working url.

    :param adlist: List of dictionaries with address and comment fields
    :return: A list of dictionary with address and comment fields, only containing the elements with a working url
    """
    return [e for e in adlist if test_url(e["address"])]


def build_custom_filtering_rules(
    whitelist_exact, blacklist_exact, whitelist_regex, blacklist_regex
) -> str:
    """
    Builds a custom filtering rules string from the provided lists.

    :param whitelist_exact: List of dictionaries with domain and comment fields
    :param blacklist_exact: List of dictionaries with domain and comment fields
    :param whitelist_regex: List of dictionaries with domain and comment fields
    :param blacklist_regex: List of dictionaries with domain and comment fields
    :return: A string containing the custom filtering rules
    """
    textblock = ""

    textblock += "! Whitelist\n"
    for entry in whitelist_exact:
        textblock += f"# {entry['comment']}\n@@|{entry['domain']}^\n"

    for entry in whitelist_regex:
        textblock += f"# {entry['comment']}\n@@/{entry['domain']}/\n"

    textblock += "\n\n"
    textblock += "! Blacklist\n"
    for entry in blacklist_exact:
        textblock += f"# {entry['comment']}\n|{entry['domain']}^\n"

    for entry in blacklist_regex:
        textblock += f"# {entry['comment']}\n/{entry['domain']}/\n"

    return textblock


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 convert_config.py <teleporter archive path>")
        sys.exit(1)
    archive_path = sys.argv[1]
    temp_dir = unzip_tar_gz(archive_path)
    try:
        adlist = read_adlist(temp_dir)
        adlist = filter_working_adlist(adlist)
        whitelist_exact = read_whitelist_exact(temp_dir)
        blacklist_exact = read_blacklist_exact(temp_dir)
        whitelist_regex = read_whitelist_regex(temp_dir)
        blacklist_regex = read_blacklist_regex(temp_dir)
        custom_filtering_rules = build_custom_filtering_rules(
            whitelist_exact, blacklist_exact, whitelist_regex, blacklist_regex
        )

        print(f"Add each of the following blocklist to the DNS blocklists page:\n\n")

        for addlist_entry in adlist:
            print(f"Name: {addlist_entry['comment']}")
            print(f"URL: {addlist_entry['address'].replace('\\/', '/')}")
            print(f"\n\n")

        print(f"Copy past this in the Custom filtering rules field:\n\n")
        print(custom_filtering_rules)
    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    main()

    exit(0)
