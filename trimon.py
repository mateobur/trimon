#!/usr/bin/python

import smtplib
import sys
import string
import random
from datetime import datetime
from email.mime.text import MIMEText
import easyimap
import re
import time
import os
import socket
import json
import mechanize
import cookielib
import subprocess
import pytz
import ConfigParser

def idGenerator(size=10, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    return ''.join(random.choice(chars) for _ in range(size))

def sendAlert(module, body, alertType = 'nonPassed'):
    if not config.getboolean('Alerting', 'enabled'):
        return
    recipient = config.get('Alerting', 'recipient')
    sender = config.get('Alerting', 'sender_addr')
    msg = MIMEText(body)
    now = datetime.now(pytz.utc)
    day = now.strftime('%a')
    date = now.strftime('%d %b %Y %X')
    if alertType == 'exception':
        msg['Subject'] = 'Exception running module: ' + module
    if alertType == 'nonPassed':
        msg['Subject'] = 'Alert in module: ' + module
    if alertType == 'success':
        msg['Subject'] = 'Successful run'
    msg['From'] = sender
    msg['To'] = recipient
    msg['Date'] = day + ', ' + date + ' -0000'
    server = config.get('Alerting', 'sender_server')
    session = smtplib.SMTP(server, config.getint('Alerting','server_SMTP_port'))
    session.ehlo()
    session.starttls()
    session.ehlo()
    session.login(sender, config.get('Alerting', 'sender_pass'))
    session.sendmail(sender, recipient, msg.as_string())
    session.quit()

def checkPing():
    return subprocess.check_call(['ping', '-c 4', config.get('General', 'target')]) == 0

def checkPorts():
    portlist = json.loads(config.get('Ports', 'ports_list'))
    for port in portlist:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((config.get('General', 'target'),port))
        sock.close()
        if result != 0:
            return False
    return True

'''
def checkWebs(urls, strings):
    browser = mechanize.Browser()
    cj = cookielib.LWPCookieJar()
    browser.set_cookiejar(cj)
    browser.set_handle_redirect(True)
    browser.set_handle_robots(False)
    browser.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]
    for url in urls:
        response = browser.open(url)
    if response.code != 200:
        return 'Badcode'
    text = response.read()
    if 'Estomagando' not in text:
        return 'NoString'
    return True
'''

def checkUptime():
    output = subprocess.check_output("ssh " + config.get('General', 'ssh_login') + " cat /proc/loadavg", shell=True)
    if float(output.split()[0]) > 2.0:
        return False
    return True

def checkServices():
    service_list = json.loads(config.get('Services', 'services_list'))
    for service in service_list:
        output = subprocess.check_output("ssh " + config.get('General', 'ssh_login') +" /etc/init.d/" + service + " status", shell=True)
        if not 'running' in output:
            return False
    return True

def checkMem():
    output = subprocess.check_output("ssh " + config.get('General', 'ssh_login') + " free", shell=True).split()
    swapTotal = output[output.index('Swap:') + 1]
    swapUsed = output[output.index('Swap:') + 2]
    if float(swapUsed) / float(swapTotal) > 0.4:
        return False
    return True

def checkMail():
    messageID = idGenerator()
    msg = MIMEText('<code>' + messageID + '</code>')
    session = smtplib.SMTP(config.get('Mail', 'sender_server'), config.getint('Mail', 'sender_SMTP_port'))
    now = datetime.now(pytz.utc)
    day = now.strftime('%a')
    date = now.strftime('%d %b %Y %X')
    msg['Subject'] = 'Trimon check mail'
    msg['From'] = config.get('Mail', 'sender_addr')
    msg['To'] = config.get('Mail', 'recipient_addr')
    msg['Date'] = day + ', ' + date + ' -0000'
    session.ehlo()
    session.starttls()
    session.ehlo()
    session.login(config.get('Mail', 'sender_addr'), config.get('Mail', 'sender_pass'))
    session.sendmail(config.get('Mail', 'sender_addr'), config.get('Mail', 'recipient_addr'), msg.as_string())
    session.quit()
    time.sleep(2)
    check = easyimap.connect(config.get('Mail', 'recipient_server'), config.get('Mail', 'recipient_addr'), config.get('Mail', 'recipient_pass'))
    mail = check.listup(1)
    code = re.search('<code>(.*)</code>',mail[0].body).group(1)
    if code == messageID:
        return True
    return False


config = ConfigParser.ConfigParser()
config.read('trimon.conf')

urls = ["http://noblezabaturra.org"]

try:
    if not checkPing():
        sendAlert('ping','no reply')
except Exception, e:
    sendAlert('ping',str(e),'exception')

try:
    if not checkPorts():
        sendAlert('Ports','not open')
except Exception, e:
    sendAlert('ports',str(e),'exception')

try:
    if not checkMail():
        sendAlert('mail','not received')
except Exception, e:
    sendAlert('mail',str(e),'exception')
'''
try:
    if not checkWebs(urls, strings):
        sendAlert('webs','not present')
except Exception, e:
    sendAlert('webs',str(e),'exception')
'''

try:
    if not checkServices():
        sendAlert('service','not running')
except Exception, e:
    sendAlert('service',str(e),'exception')

try:
    if not checkMem():
        sendAlert('mem','out of mem')
except Exception, e:
    sendAlert('mem',str(e),'exception')

if config.getboolean('General', 'mail_success'):
    sendAlert('any', 'all tests passed', 'success')

