# netcon.py V2.1.2
#
# Copyright (c) 2020 NetCon Unternehmensberatung GmbH, https://www.netcon-consulting.com
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

"""
Collection of functions for Clearswift external commands.
"""

import argparse
from collections import namedtuple
from email import message_from_binary_file
from xml.sax import make_parser, handler, SAXException
from io import BytesIO
import re
import toml
import pyzipper
from bs4 import BeautifulSoup

class ParserArgs(argparse.ArgumentParser):
    """
    Argument parser for config, input and log files.
    """
    def __init__(self, description, config_default=None):
        """
        :type description: str
        :type config_default: str
        """
        super().__init__(description=description)

        if config_default is not None:
            self.add_argument(
                "-c",
                "--config",
                metavar="CONFIG",
                type=str,
                default=config_default,
                help="path to configuration file (default={})".format(config_default)
            )

        self.add_argument("input", metavar="INPUT", type=str, help="input file")
        self.add_argument("log", metavar="LOG", type=str, help="log file")

class SAXExceptionFinished(SAXException):
    """
    Custom SAXException for stopping parsing after all info has been read.
    """
    def __init__(self):
        super().__init__("Stop parsing")

class HandlerAddressList(handler.ContentHandler):
    """
    Custom content handler for xml.sax for extracting address list from CS config.
    """
    def __init__(self, name_list):
        """
        :type name_list: str
        """
        self.name_list = name_list
        self.set_address = set()
        self.list_found = False
        self.add_address = False

        super().__init__()

    def startElement(self, name, attrs):
        if not self.add_address:
            if name == "AddressList" and "name" in attrs and attrs["name"] == self.name_list:
                self.list_found = True
            elif self.list_found and name == "Address":
                self.add_address = True

    def characters(self, content):
        if self.add_address:
            self.set_address.add(content)

    def endElement(self, name):
        if self.list_found and (name == "AddressList"):
            raise SAXExceptionFinished

    def getAddresses(self):
        """
        Return email addresses as set.

        :rtype: set
        """
        return self.set_address

class HandlerExpressionList(handler.ContentHandler):
    """
    Custom content handler for xml.sax for extracting expression list from CS config.
    """
    def __init__(self, name_list):
        """
        :type name_list: str
        """
        self.name_list = name_list
        self.set_expression = set()
        self.list_found = False

        super().__init__()

    def startElement(self, name, attrs):
        if name == "TextualAnalysis" and "name" in attrs and attrs["name"] == self.name_list:
            self.list_found = True
        elif self.list_found and name == "Phrase" and "text" in attrs:
            self.set_expression.add(attrs["text"])

    def endElement(self, name):
        if self.list_found and (name == "TextualAnalysis"):
            raise SAXExceptionFinished

    def getExpressions(self):
        """
        Return expressions as set.

        :rtype: set
        """
        return self.set_expression

def read_file(path_file, ignore_errors=False):
    """
    Read file as string.

    :type path_file: str
    :type ignore_errors: bool
    :rtype: str
    """
    try:
        if ignore_errors:
            with open(path_file, errors="ignore") as f:
                content = f.read()
        else:
            with open(path_file) as f:
                content = f.read()
    except FileNotFoundError:
        raise Exception("'{}' does not exist".format(path_file))
    except PermissionError:
        raise Exception("Cannot open '{}'".format(path_file))
    except UnicodeDecodeError:
        raise Exception("'{}' not UTF-8".format(path_file))

    return content

def read_email(path_email):
    """
    Parse email file.

    :type path_email: str
    :rtype: email.message.Message
    """
    try:
        with open(path_email, "rb") as f:
            email = message_from_binary_file(f)
    except:
        raise Exception("Cannot parse email")

    return email

def read_config(path_config, parameters_config):
    """
    Read config file and check all required config parameters are defined.

    :type path_config: str
    :type parameters_config: set
    :rtype: namedtuple
    """
    config = read_file(path_config)

    try:
        config = toml.loads(config)
    except:
        raise Exception("Cannot parse config")

    # discard all parameters not defined in parameters_config
    config = { param_key: param_value for (param_key, param_value) in config.items() if param_key in parameters_config }

    # check for missing parameters
    parameters_missing = parameters_config - config.keys()

    if parameters_missing:
        raise Exception("Missing parameters {}".format(str(parameters_missing)[1:-1]))

    TupleConfig = namedtuple("TupleConfig", parameters_config)

    return TupleConfig(**config)

def write_log(path_log, message):
    """
    Write message to log file.

    :type message: str
    :type path_log: str
    """
    LOG_PREFIX = ">>>>"
    LOG_SUFFIX = "<<<<"

    with open(path_log, "a") as file_log:
        file_log.write("{}{}{}\n".format(LOG_PREFIX, message, LOG_SUFFIX))

def get_address_list(name_list, last_config="/var/cs-gateway/deployments/lastAppliedConfiguration.xml"):
    """
    Extract address list from CS config and return addresses as set.

    :type name_list: str
    :type last_config: str
    :rtype: set
    """
    parser = make_parser()
    address_handler = HandlerAddressList(name_list)
    parser.setContentHandler(address_handler)

    try:
        parser.parse(last_config)
    except SAXExceptionFinished:
        pass

    return address_handler.getAddresses()

def get_expression_list(name_list, last_config="/var/cs-gateway/deployments/lastAppliedConfiguration.xml"):
    """
    Extract expression list from CS config and return expressions as set.

    :type name_list: str
    :type last_config: str
    :rtype: set
    """
    parser = make_parser()
    expression_handler = HandlerExpressionList(name_list)
    parser.setContentHandler(expression_handler)

    try:
        parser.parse(last_config)
    except SAXExceptionFinished:
        pass

    return expression_handler.getExpressions()

def zip_encrypt(set_data, password):
    """
    Create encrypted zip archive from set of data with defined password and return as bytes.

    :type set_data: set
    :type password: str
    :rtype: bytes
    """
    buffer = BytesIO()

    with pyzipper.AESZipFile(buffer, "w", compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
        zf.pwd = password

        for (file_name, data) in set_data:
            zf.writestr(file_name, data)

    return buffer.getvalue()

def unzip_decrypt(bytes_zip, password):
    """
    Extract encrypted zip archive with defined password and return as set of data.

    :type bytes_zip: bytes
    :type password: str
    :rtype: set
    """
    with pyzipper.AESZipFile(BytesIO(bytes_zip), "r", compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
        zf.pwd = password

        set_data = set()

        for file_name in zf.namelist():
            set_data.add((file_name, zf.read(file_name)))

    return set_data

def end_escape(string):
    """
    Check string ending in uneven number of backslashes.

    :type string: str
    :rtype: bool
    """
    num_blackslash = 0

    for char in string[::-1]:
        if char == "\\":
            num_blackslash = num_blackslash + 1
        else:
            break

    return num_blackslash % 2 != 0

def extract_addresses(string, discard_unparsable=True):
    """
    Extract email addresses with prefix and suffix from string.

    :type string: str
    :type discard_unparsable: bool
    :rtype: list
    """
    PATTERN_WITH_BRACKETS = re.compile(r'(.*?<)([^<",;\s]+@[^>",;\s]+)(>.*)')
    PATTERN_NO_BRACKETS = re.compile(r'(.*?)([^<",;\s]+@[^>",;\s]+)(.*)')
    PATTERN_QUOTE = re.compile(r'"')

    list_chunk = [ 0, ]

    for match in re.finditer(r"(;|,)", string):
        index = match.start(0)

        if not end_escape(string[:index]):
            list_chunk.append(index)

    index = len(list_chunk) - 1
    rest = string

    list_address = list()

    while index >= 0:
        chunk = rest[list_chunk[index]:]
        rest = rest[:list_chunk[index]]

        match = re.search(PATTERN_WITH_BRACKETS, chunk)

        if not match:
            match = re.search(PATTERN_NO_BRACKETS, chunk)

        if match:
            prefix = match.group(1)
            email = match.group(2)
            suffix = match.group(3)

            while True:
                num_quote = 0

                for match in re.finditer(PATTERN_QUOTE, prefix):
                    if not end_escape(prefix[:match.start(0)]):
                        num_quote = num_quote + 1

                if num_quote % 2 == 0:
                    break

                index = index - 1

                if index < 0:
                    break

                prefix = rest[list_chunk[index]:] + prefix
                rest = rest[:list_chunk[index]]

            list_address.append(( prefix, email, suffix ))
        elif not discard_unparsable:
            list_address.append(( chunk, "", "" ))

        index = index - 1

    list_address.reverse()

    return list_address

def extract_email_addresses(string):
    """
    Extract multiple email addresses from string and return as set.

    :type string: str
    :rtype: set
    """
    list_address = extract_addresses(string)

    if list_address:
        return { email for (_, email, _) in list_address }
    else:
        return None

def extract_email_address(string):
    """
    Extract single email address from string.

    :type string: str
    :rtype: str
    """
    list_address = extract_addresses(string)

    if list_address:
        (_, email, _) = list_address[0]

        return email
    else:
        return None

def html2text(html, strip=True):
    """
    Extract text from html.

    :type html: str
    :type strip: bool
    :rtype: str
    """
    soup = BeautifulSoup(html, features="html5lib")

    for script in soup([ "script", "style" ]):
        script.extract()

    text = soup.get_text()

    if strip:
        lines = ( line.strip() for line in text.splitlines() )

        chunks = ( phrase.strip() for line in lines for phrase in line.split("  ") )

        text = "\n".join( chunk for chunk in chunks if chunk )

    return text
