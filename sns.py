#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from datetime import *
import nmap
import getpass
import sys
import telnetlib
import smtplib
from email.mime.text import MIMEText

# Configuration ###########################################################
conf = {"LAN": "192.168.1.0/24",
        "IP_ROUTE": "192.168.1.1",
        "MAC_SERVER": "88:88:88:88:88:88",
        "ROUTE_USER": "admin",
        "ROUTE_PASS": "admin",
        "PORT": {80: "HTTP",
                 443: "HTTPS",
                 },
        "NMAP_ARG": "-sP",
        "SMTP": "smtp.server.com",
        "SMTP_PORT": "587",
        "SMTP_USER": "user@server.com",
        "SMTP_PASS": "password",
        "EMAIL_DESTINO": "me@endikaiglesias.com",
        "EMAIL_ORIGEN": "yo@endikaiglesias.com",
        "ASUNTO": "Alerta Wifi",
        "LOG_FILE": "/var/log/small_network_scanner.log"
        }

network = {"Router": {"MAC": {"00:00:00:00:00:00": "eth0"},
                      "PORT": {23: "Telnet"},
                      "EMAIL": {"me@endikaiglesias.com": "Endika"},
                      "IP": "192.168.1.1",
                      "INFO": "Router Wifi"
                      },
           "Endika Personal": {"MAC": {"11:11:11:11:11:11": "wlan0",
                                       "22:22:22:22:22:22": "eth0",
                                       },
                               "EMAIL": {"me@endikaiglesias.com": "Endika"},
                               "INFO": "Laptop"
                               },
           "Public PC": {"MAC": {"33:33:33:33:33:33": "eth0"},
                         "EMAIL": {"me@endikaiglesias.com": "Endika",
                                   "yo@endikaiglesias.com": "Endika2"
                                   },
                         "INFO": "PC Public"
                         },
           "Raspberry Pi": {"MAC": {"88:88:88:88:88:88": "eth0"},
                            "PORT": {22: "SSH", 587: "SMTP"},
                            "EMAIL": {"me@endikaiglesias.com": "Endika"},
                            "IP": "192.168.1.39",
                            "INFO": "Server Linux"
                            },
           "HTC": {"MAC": {"44:44:44:44:44:44": "wlan0"},
                   "EMAIL": {"me@endikaiglesias.com": "Endika"},
                   "INFO": "Personal Phone"
                   },
           }

msg = {'write': 'Error en la escritura del log',
       'deny_mac': 'Error al bloquear la dirección MAC',
       'send_mail': 'Error al enviar el email',
       'reboot': 'Error al reiniciar el router',
       }
# ############# ###########################################################


def _registrar(texto):
    if 'LOG_FILE' in conf.keys():
        fm = open(conf["LOG_FILE"], "a")
        fm.write(texto)
        fm.close()
        return True
    return False


def _send_mail(mensaje, email=conf['EMAIL_DESTINO']):
    if 'SMTP' in conf.keys() and \
       'SMTP_PORT' in conf.keys() and \
       'SMTP_USER' in conf.keys() and \
       'SMTP_PASS' in conf.keys() and \
       'EMAIL_ORIGEN' in conf.keys() and \
       'ASUNTO' in conf.keys():

        mailServer = smtplib.SMTP(conf['SMTP'], conf['SMTP_PORT'])
        mailServer.ehlo()
        mailServer.starttls()
        mailServer.ehlo()
        mailServer.login(conf['SMTP_USER'], conf['SMTP_PASS'])
        mensaje = MIMEText(str(mensaje))
        mensaje['From'] = conf['EMAIL_ORIGEN']
        mensaje['To'] = email
        mensaje['Subject'] = conf['ASUNTO']
        mailServer.sendmail(conf['EMAIL_ORIGEN'],
                            email,
                            mensaje.as_string())
        mailServer.close()
        return True
    return False


def _reboot_wifi():
    if 'IP_ROUTE' in conf.keys() and \
       'ROUTE_USER' in conf.keys() and \
       'ROUTE_PASS' in conf.keys():

        tn = telnetlib.Telnet(conf['IP_ROUTE'])
        tn.read_until("Login: ")
        tn.write(conf['ROUTE_USER'] + "\n")
        tn.read_until("Password: ")
        tn.write(conf['ROUTE_PASS'] + "\n")
        tn.write("save_and_reboot\n")
        tn.write("exit\n")
        print tn.read_all()
        return True
    return False


def _deny_mac(mac):
    if 'IP_ROUTE' in conf.keys() and \
       'ROUTE_USER' in conf.keys() and \
       'ROUTE_PASS' in conf.keys():

        tn = telnetlib.Telnet(conf['IP_ROUTE'])
        tn.read_until("Login: ")
        tn.write(conf['ROUTE_USER'] + "\n")
        tn.read_until("Password: ")
        tn.write(conf['ROUTE_PASS'] + "\n")
        tn.write("wlan macfilter --mode deny\n")
        tn.write("wlan macfilter --add " + str(mac.lower()) + "\n")
        tn.write("exit\n")
        print tn.read_all()
        return True
    return False


def _validate():
    # TODO implementar un validador inicial
    return True


def main():
    _validate()
    DEFCON = 0  # Nivel de peligrosidad en el analisis
    nm = nmap.PortScanner()
    now = datetime.today()

    if not _registrar("Iniciando chequeo "+str(now)+"\n"):
        print msg['write']
    print ("Iniciando chequeo "+str(now))
    # Scaneamos la red
    print "Network scanning..."
    nm.scan(hosts=conf['LAN'], arguments=conf['NMAP_ARG'])

    print "Analyzing..."
    # all_mac = [j for i in network for j in network[i]['MAC'].keys()]
    c = 1
    t = str(len(nm.all_hosts()))

    for host in nm.all_hosts():

        print str(c) + " de " + t
        c += 1

        # Validar dirección MAC
        nm_mac = ''
        if 'mac' in nm[host]['addresses'].keys():
            nm_mac = nm[host]['addresses']['mac']
        else:
            nm_mac = conf['MAC_SERVER']

        network_key = [i for i
                       in network
                       if nm_mac in network[i]['MAC'].keys()]
        if len(network_key) > 0:
            network_key = network_key[0]
        else:
            network_key = nm_mac

        if network_key not in network.keys():
            text = "INTRUSO DETECTADO IP: "+str(host) + \
                   " y su MAC: " + str(nm_mac) + \
                   " MAC no registrada\n"

            if not _deny_mac(nm_mac):
                print msg['deny_mac']
            DEFCON = 2 if DEFCON < 2 else DEFCON
            print text
            if not _registrar(text):
                print msg['write']
            if not _send_mail(text):
                print msg['send_mail']
            continue

        # Validar dirección IP si la tiene
        if 'IP' in network[network_key].keys() and \
           host != network[network_key]['IP']:

            text = "INTRUSO DETECTADO IP: "+str(host) + \
                   " y su MAC: " + str(nm_mac) + \
                   " IP no coincide\n"
            if not _deny_mac(nm_mac):
                print msg['deny_mac']
            DEFCON = 3 if DEFCON < 3 else DEFCON
            print text
            if not _registrar(text):
                print msg['write']
            if 'EMAIL' in network[network_key].keys():
                for email in network[network_key].keys():
                    if not _send_mail(text, email):
                        print msg['send_mail']
            else:
                if not _send_mail(text):
                    print msg['send_mail']

        # Validar puertos
        permit_port = conf['PORT']
        if 'PORT' in network[network_key].keys():
            for port in network[network_key]['PORT'].keys():
                if port not in permit_port:
                    permit_port[port] = network[network_key]['PORT'][port]

        if 'udp' in nm[host].all_protocols():
            for port in nm[host]['udp'].keys():
                if port not in permit_port:
                    name = network_key
                    text = "IP: " + str(host) + " PORT: " + \
                           str(port) + "(UDP) MAC: " + str(nm_mac) + \
                           " Name: " + str(name) + "\n"
                    DEFCON = 1 if DEFCON < 1 else DEFCON
                    print text
                    if not _registrar(text):
                        print msg['write']
                    if 'EMAIL' in network[network_key].keys():
                        for email in network[network_key].keys():
                            if not _send_mail(text, email):
                                print msg['send_mail']
                    else:
                        if not _send_mail(text):
                            print msg['send_mail']

        if 'tcp' in nm[host].all_protocols():
            for port in nm[host]['tcp'].keys():
                if port not in permit_port:
                    name = network_key
                    text = "IP: " + str(host) + " PORT: " + \
                           str(port) + "(TCP) MAC: " + str(nm_mac) + \
                           " Name: " + str(name) + "\n"
                    DEFCON = 1 if DEFCON < 1 else DEFCON
                    print text
                    if not _registrar(text):
                        print msg['write']
                    if 'EMAIL' in network[network_key].keys():
                        for email in network[network_key].keys():
                            if not _send_mail(text, email):
                                print msg['send_mail']
                    else:
                        if not _send_mail(text):
                            print msg['send_mail']

    # Ejecutar acciones según resultados
    if not _registrar("DEFCON: "+str(DEFCON)+"\n"):
        print msg['write']
    if DEFCON == 0:
        print "Todo OK"
    elif DEFCON == 1:
        print "Hay que echar un ojo"
    elif DEFCON == 2:
        print "Reiniciamos el ROUTER"
        if not _reboot_wifi():
            print msg['reboot']
    elif DEFCON == 3:
        print "Reiniciamos el ROUTER"
        if not _reboot_wifi():
            print msg['reboot']
        """
        print "Spoofeamos la red"
        os.system('service apache2 start')
        os.system('ettercap -T -q -P autoadd -M arp // // -i eth0' +
                  ' & ettercap -T -q -P dns_spoof -i eth0')
        """
    else:
        print "NO IMPLEMENTADO"
    text = "Chequeo finalizado con exito "+str(datetime.today())+"\n"
    if not _registrar(text):
        print msg['write']
    if not _registrar("---\n"):
        print msg['write']

main()
# FIN PROGRAMA
