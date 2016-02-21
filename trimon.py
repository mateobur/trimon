#!/usr/bin/python

import smtplib
import string
import random
from datetime import datetime
from email.mime.text import MIMEText
import re
import time
import os
import socket
import json
import mechanize
import cookielib
import subprocess
import traceback
import pytz
import imaplib
import email
import signal
import ConfigParser


def idGenerator(
        size=10,
        chars=string.ascii_uppercase +
        string.digits +
        string.ascii_lowercase):
    return "".join(random.choice(chars) for _ in range(size))


def handler(signum, frame):
    raise Exception("Time out exception")


def sendAlert(module, body, alertType="nonPassed"):
    if not config.getboolean("Alerting", "enabled"):
        return
    recipient = config.get("Alerting", "recipient")
    sender = config.get("Alerting", "sender_addr")
    msg = MIMEText(body)
    now = datetime.now(pytz.utc)
    day = now.strftime("%a")
    date = now.strftime("%d %b %Y %X")
    if alertType == "exception":
        msg["Subject"] = "Exception running module: " + module
    if alertType == "nonPassed":
        msg["Subject"] = "Alert in module: " + module
    if alertType == "success":
        msg["Subject"] = "Successful run"
    msg["From"] = sender
    msg["To"] = recipient
    msg["Date"] = day + ", " + date + " -0000"
    server = config.get("Alerting", "sender_server")
    session = smtplib.SMTP(
        server,
        config.getint(
            "Alerting",
            "server_SMTP_port"))
    session.ehlo()
    session.starttls()
    session.ehlo()
    session.login(sender, config.get("Alerting", "sender_pass"))
    session.sendmail(sender, recipient, msg.as_string())
    session.quit()


def checkPing():
    return subprocess.check_call(
        ["ping", "-c 4", config.get("General", "target")],
        stdout=open(os.devnull, "w")) == 0, "no ping"


def checkPorts():
    portlist = json.loads(config.get("Ports", "ports_list"))
    for port in portlist:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((config.get("General", "target"), port))
        sock.close()
        if result != 0:
            return False, "port " + str(port) + " is closed"
    return True, None


def checkWebs():
    browser = mechanize.Browser()
    cj = cookielib.LWPCookieJar()
    browser.set_cookiejar(cj)
    browser.set_handle_redirect(True)
    browser.set_handle_robots(False)
    browser.addheaders = [
        ("User-agent",
         "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) " +
         "Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1")]
    urls = json.loads(config.get("Webs", "url_check"))
    for url_check in urls:
        response = browser.open(url_check[0])
        if response.code != 200:
            return False, "HTTP code " + response.code
        text = response.read()
        for i in range(1, len(url_check)):
            if str(url_check[i]) not in text:
                return False, "String '" + \
                    url_check[i] + "' not found in webpage '" + \
                    url_check[0] + "'"
    return True, None


def sysCommand(cmd, sudo=False):
    sysString = ""
    if (sudo):
        sysString += "echo " +\
            config.get(
                "General",
                "ssh_pass") + " | "
    sysString += "ssh " +\
        config.get(
            "General",
            "ssh_login")
    if (sudo):
        sysString += " sudo -S"
    sysString += " " + cmd
    return subprocess.check_output(sysString, shell=True)


def checkLoad():
    output = sysCommand("cat /proc/loadavg")
    if float(output.split()[0]) > config.getfloat("Load", "threshold"):
        return False, "System load above threshold: " + output
    return True, None


def checkServices():
    output = sysCommand("netstat -wantup | grep LISTEN", True)
    service_list = json.loads(config.get("Services", "services_list"))
    for service in service_list:
        if service not in output:
            return False, "Service " + service + " is not listening"
    return True, None


def checkMem():
    output = sysCommand("free").split()
    swapTotal = output[output.index("Swap:") + 1]
    swapUsed = output[output.index("Swap:") + 2]
    if float(swapUsed) / float(swapTotal) > \
       config.getfloat("Mem", "swap_used_threshold"):
            return False
    return True, None


def checkMail():
    messageID = idGenerator()
    msg = MIMEText("<code>" + messageID + "</code>")
    session = smtplib.SMTP(
        config.get(
            "Mail", "sender_server"), config.getint(
            "Mail", "sender_SMTP_port"))
    now = datetime.now(pytz.utc)
    day = now.strftime("%a")
    date = now.strftime("%d %b %Y %X")
    msg["Subject"] = "Trimon check mail"
    msg["From"] = config.get("Mail", "sender_addr")
    msg["To"] = config.get("Mail", "recipient_addr")
    msg["Date"] = day + ", " + date + " -0000"
    session.ehlo()
    session.starttls()
    session.ehlo()
    session.login(
        config.get(
            "Mail", "sender_addr"), config.get(
            "Mail", "sender_pass"))
    session.sendmail(
        config.get(
            "Mail", "sender_addr"), config.get(
            "Mail", "recipient_addr"), msg.as_string())
    session.quit()
    time.sleep(10)
    M = imaplib.IMAP4_SSL(config.get("Mail", "recipient_server"))
    M.login(
        config.get(
            "Mail", "recipient_addr"), config.get(
            "Mail", "recipient_pass"))
    M.select("INBOX")
    status, data = M.sort("REVERSE DATE", "UTF-8", "ALL")
    email_id = data[0].split()[0]
    status, data = M.fetch(email_id, "(RFC822)")
    msg = email.message_from_string(data[0][1])
    code = re.search("<code>(.*)</code>", msg.get_payload()).group(1)
    if code == messageID:
        if config.getboolean("Mail", "delete_test_email"):
            M.store(email_id, "+FLAGS", "\\Deleted")
            M.expunge()
            M.close()
            M.logout()
        return True, None
    return False, "Email was not correctly received"

config = ConfigParser.ConfigParser()
config.read("trimon.conf")

checks = ["Ping", "Ports", "Load", "Mem", "Mail", "Services", "Webs"]

all_success = True
signal.signal(signal.SIGALRM, handler)

for check in checks:
    if config.getboolean(check, "enabled"):
        signal.alarm(20)
        try:
            methodToCall = locals()["check" + check]
            success, reason = methodToCall()
            if not success:
                all_success = False
                sendAlert(check, reason)
        except Exception as e:
            all_success = False
            sendAlert(check, str(e), "exception")
            print traceback.print_exc()
        signal.alarm(0)


if all_success:
    print "All tests passed successfully"

if config.getboolean("General", "mail_success") and all_success:
    sendAlert("any", "all tests passed", "success")
