import ConfigParser
import psycopg2
import re
from copy import copy

config_filename = '/etc/barman.d/5432.conf'
config = ConfigParser.RawConfigParser()
config.read(config_filename)

connstr = config.get('CLUSTER_5432', 'conninfo')
conninfo = dict([ part.split('=', 1) for part in connstr.split(' ') ])
servers = conninfo['host'].split(',')
masters = []
for server in servers:
    try:
        conninfo['host'] = server
        connstring = ' '.join([ '{0}={1}'.format(k, v) for k, v in conninfo.items()])
        conn =  psycopg2.connect(connstring)
        cur = conn.cursor()
        cur.execute('select pg_is_in_recovery()')
        if not cur.fetchone()[0]:
            masters.append(server)
    except psycopg2.OperationalError:
        pass
if len(masters) == 1:
    ssh_command = config.get('CLUSTER_5432', 'ssh_command')
    ssh_command = re.sub('@\S+', '@'+masters[0], ssh_command, 1)
    config.set('CLUSTER_5432', 'ssh_command', ssh_command)
    print('Writing correct config to {0}'.format(config_filename))
    with open(config_filename, 'wb') as configfile:
        config.write(configfile)
