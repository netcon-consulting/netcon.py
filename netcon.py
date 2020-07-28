# netcon.py V2.0.0
#
# Copyright (c) 2020 NetCon Unternehmensberatung GmbH, https://www.netcon-consulting.com
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

"""
Collection of functions for Clearswift external commands.
"""

import argparse
from collections import namedtuple
from email import message_from_string
from xml.sax import make_parser, handler, SAXException
from io import BytesIO
import re
import toml
import pyzipper
from bs4 import BeautifulSoup

PATTERN_EMAIL_ADDRESS = re.compile(r'.*?([^<",;\s]+@[^>",;\s]+)')

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
    Read email file and parse contents.

    :type path_email: str
    :rtype: email.message.Message
    """
    email = read_file(path_email)

    try:
        email = message_from_string(email)
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

def extract_email_addresses(string):
    """
    Extract multiple email addresses from string and return as set.

    :type string: str
    :rtype: set
    """
    email_addresses = re.findall(PATTERN_EMAIL_ADDRESS, string)

    if email_addresses:
        return set(email_addresses)

    return None

def extract_email_address(string):
    """
    Extract single email address from string.

    :type string: str
    :rtype: str
    """
    email_address = re.search(PATTERN_EMAIL_ADDRESS, string)

    if email_address:
        return email_address.group(1)

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
