#!/usr/bin/python
# 
# pdns-redis.py, Copyright 2011, Bjarni R. Einarsson <http://bre.klaki.net/>
#                                and The Beanstalks Project ehf.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
BANNER = "pdns-redis.py, by Bjarni R. Einarsson"
DOC = """\
pdns-redis.py is Copyright 2011, Bjarni R. Einarsson, http://bre.klaki.net/
                                 and The Beanstalks Project ehf.

This program implements a PowerDNS pipe-backend for looking up domain info in a
Redis database.  It also includes basic CLI functionality for querying, setting
and deleting DNS records in Redis.

Usage: pdns-redis.py [-R <host:port>] [-A <password-file>] [-P]
       pdns-redis.py [-R <host:port>] [-A <password-file>] 
                     [-D <domain>] [-r <type>] [-d <data>] [-k] [-q] [-a <ttl>] 

Flags:

  -R <host:port>     Set the Redis back-end.
  -A <password-file> Read a Redis password from the named file.
  -P                 Run as a PowerDNS pipe-backend. 
  -D <domain>        Select a domain for --query or --set.
  -r <record-type>   Choose which record to modify/query/delete.
  -d <data>          Data we are looking for or adding.
  -z                 Reset record and data.
  -q                 Query.
  -k                 Kill (delete).
  -A <ttl>           Add using a given TTL (requires -r and -d).  The TTL
                     may be 

WARNING: This program does NOTHING to ensure the records you create are valid
         according to the DNS spec.  Use at your own risk!

Queries and kills (deletions) are filtered by -r and -d, if present.  If
neither is specified, the entire domain is processed.

Note that argumemnts are processed in order so multiple adds and deletes can
be done at once, just by repeating the -D, -r, -d, -k and -a arguments, varying
the data as you go along.

Examples:

  # Configure an A and two MX records for domain.com.
  pdns-redis.py -R localhost:9076 -D domain.com \\
                -r A -d 1.2.3.4 -a 5M \\ 
                -r MX -d '10 mx1.domain.com.' -a 1D \\
                      -d '20 mx2.domain.com.' -a 1D

  # Delete all CNAME records for foo.domain.com
  pdns-redis.py -R localhost:9076 -D foo.domain.com -r CNAME -k

  # Delete the 2nd MX from domain.com
  pdns-redis.py -R localhost:9076 -D domain.com -d '20 mx2.domain.com.' -k

  # Make self.domain.com return the IP of the DNS server
  pdns-redis.py -R localhost:9076 -D self.domain.com -r A -d self -a 5M 

  # Delete domain.com completely
  pdns-redis.py -R localhost:9076 -D bar.domain.com -k

  # Chat with pdns-redis.py using the PowerDNS protocol
  pdns-redis.py -R localhost:9076 -P

"""

import sys
import getopt
import redis
import socket

OPT_COMMON_FLAGS = 'A:R:z'
OPT_COMMON_ARGS = ['auth=', 'redis=', 'reset']
OPT_FLAGS = 'PD:r:d:kqa:'
OPT_ARGS = ['pdnsbe', 'domain', 'record', 'data', 'kill', 'delete', 'query',
            'add']

VALID_RECORDS = ['A', 'NS', 'MX', 'CNAME', 'SOA', 'TXT']
TTL_SUFFIXES = {
  'M': 60,
  'H': 60*60,
  'D': 60*60*24,
  'W': 60*60*24*7,
}
MAGIC_SELF_IP = 'self'


class MockRedis(object):
  """A mock-redis object for quick offline tests."""
  def __init__(self, host=None, port=None, password=None):
    self.data = {}
  def ping(self): return True 
  def get(self, key):
    if key in self.data: return self.data[key]
    return None
  def set(self, key, val):
    self.data[key] = val
  def setnx(self, key, val):
    if key in self.data: return None
    self.data[key] = val
    return val
  def incr(self, key):
    if key not in self.data: self.data[key] = 0
    self.data[key] += 1
    return self.data[key]
  def incrby(self, key, val):
    if key not in self.data: self.data[key] = 0
    self.data[key] += val
    return self.data[key]
  def delete(self, key):
    if key in self.data: del(self.data[key])
  def hget(self, key, hkey):
    if key in self.data and hkey in self.data[key]: return self.data[key][hkey]
    return None
  def hincrby(self, key, hkey, val):
    if key not in self.data: self.data[key] = {}
    if hkey not in self.data[key]: self.data[key][hkey] = 0
    self.data[key][hkey] += val
    return self.data[key][hkey]
  def hgetall(self, key):
    if key in self.data: return self.data[key]
    return {}
  def hdel(self, key, hkey):
    if key in self.data and hkey in self.data[key]: del(self.data[key][hkey])
  def hset(self, key, hkey, val):
    if key not in self.data: self.data[key] = {}
    self.data[key][hkey] = val


class Error(Exception):
  pass

class ArgumentError(Exception):
  pass


class Task(object):
  """Tasks are all runnable."""

  def Run(self):
    return "Run not implemented! Woah!"


class QueryOp(Task):
  """This object will query Redis for a given record."""

  def __init__(self, redis_pdns, domain, record=None, data=None):
    if not redis_pdns:
      raise ArgumentError('Redis master object required!')
    if not domain:
      raise ArgumentError('Domain is a required parameter.')

    self.redis_pdns = redis_pdns

    # FIXME: What about i18n domains? Does this make any sense?
    self.domain = domain and domain.lower() or None
    self.record = record and record.upper() or None
    self.data = data

  def Query(self):
    pdns_be = self.redis_pdns.BE()
    pdns_key = 'pdns.'+self.domain

    if self.record and self.data:
      key = "\t".join([self.record, self.data])
      ttl = pdns_be.hget(pdns_key, key)
      if ttl is not None:
        pdns_be.hincrby(pdns_key, 'TXT\tQC', 1)
        return [(self.domain, self.record, ttl, self.data)]
      else:
        return []

    rv = []
    ddata = pdns_be.hgetall(pdns_key)

    if self.record:
      for entry in ddata:
        record, data = entry.split("\t", 1)
        if record == self.record:
          rv.append((self.domain, record, ddata[entry], data))

    elif self.data:
      for entry in ddata:
        record, data = entry.split("\t", 1)
        if data == self.data:
          rv.append((self.domain, record, ddata[entry], data))
    
    else:
      for entry in ddata:
        record, data = entry.split("\t", 1)
        rv.append((self.domain, record, ddata[entry], data))

    if rv: pdns_be.hincrby(pdns_key, 'TXT\tQC', 1)
    return rv

  def Run(self):
    return self.Query()


class DeleteOp(QueryOp):
  """This object will delete records from Redis."""

  def Run(self):
    if not self.record and not self.data:
      self.redis_pdns.BE().delete('pdns.'+self.domain) 
      return 'Deleted all records for %s.' % self.domain

    deleted = 0
    if self.record and self.data:
      deleted += self.redis_pdns.BE().hdel('pdns.'+self.domain,
                                         "\t".join([self.record, self.data]))
    else:
      for record in self.Query():
        deleted += self.redis_pdns.BE().hdel('pdns.'+self.domain,
                                           "\t".join([record[1], record[3]]))
      
    return 'Deleted %d records from %s.' % (deleted, self.domain)


class AddOp(QueryOp):
  """This object will add a record to Redis."""

  def __init__(self, redis_pdns, domain, record, data, ttl):
    QueryOp.__init__(self, redis_pdns, domain, record, data)

    if self.record not in VALID_RECORDS:
      raise ArgumentError('Invalid record type: %s' % self.record)

    if not self.data:
      raise ArgumentError('Cannot add empty records.')

    if ttl and ttl[-1].upper() in TTL_SUFFIXES:
      self.ttl = str(int(ttl[:-1]) * TTL_SUFFIXES[ttl[-1].upper()])
    else:
      self.ttl = str(int(ttl))

  def Run(self):
    self.redis_pdns.BE().hset('pdns.'+self.domain, 
                              "\t".join([self.record, self.data]), self.ttl)
    return 'Added %s record to %s.' % (self.record, self.domain)


class PdnsChatter(Task):
  """This object will chat with the pDNS server."""

  def __init__(self, infile, outfile, redis_pdns):
    self.infile = infile
    self.outfile = outfile
    self.redis_pdns = redis_pdns
    self.local_ip = None

  def reply(self, text):
    self.outfile.write(text)
    self.outfile.write("\n")
    self.outfile.flush()

  def readline(self):
    return self.infile.readline().strip()

  def SendMxOrSrv(self, d1, d2, d3, d4):
    self.reply('DATA\t%s\tIN\t%s\t%s\t-1\t%s' % (d1, d2, d3, d4))

  def SendRecord(self, record):
    if record[3] == MAGIC_SELF_IP:
      self.reply('DATA\t%s\tIN\t%s\t%s\t-1\t%s' % (record[0], record[1],
                                                   record[2], self.local_ip))
    else:
      self.reply('DATA\t%s\tIN\t%s\t%s\t-1\t%s' % record)

  def SendLog(self, message):
    self.reply('LOG\t%s' % message)

  def EndReply(self):
    self.reply('END')

  def Lookup(self, query):
    (pdns_qtype, domain, qclass, rtype, _id, remote_ip, local_ip) = query
    if not self.local_ip:
      self.local_ip = local_ip

    if self.local_ip == '0.0.0.0':
      self.local_ip = socket.getaddrinfo(socket.gethostname(), None)[0][4][0]       
    if pdns_qtype == 'Q':
      if not domain:
        records = []
      elif rtype == 'ANY':
        records = QueryOp(self.redis_pdns, domain).Query()
      else:
        records = QueryOp(self.redis_pdns, domain, rtype).Query()

      for record in records:
        if record[1] in ('MX', 'SRV'):
          data = '\t'.join(record[3].split(' ', 1))
          self.SendMxOrSrv(record[0], record[1], record[2], data)
        else:
          self.SendRecord(record)

      self.EndReply()
    else:
      self.SendLog("PowerDNS requested %s, we only do Q." % pdns_qtype)
      self.reply('FAIL')

  def Run(self):
    line1 = self.readline()
    if not line1 == "HELO\t2":
      self.reply('FAIL')
      self.readline()
      sys.exit(1)
    else:
      self.reply('OK\t%s' % BANNER)

    while 1:
      line = self.readline() 
      try:
        query = line.split("\t")
#       self.reply("LOG\tPowerDNS sent: %s" % query)
        if len(query) == 7:
          self.Lookup(query)  
        else:
          self.reply("LOG\tPowerDNS sent bad request: %s" % query)
          self.reply("FAIL")
      except ValueError, verr:
        self.reply("LOG\tInternal ValueError: %s" % verr)
        self.reply("FAIL")


class PdnsRedis(object):
  """Main loop..."""

  def __init__(self):
    self.redis_host = None
    self.redis_port = None
    self.redis_pass = None
    self.be = None
    self.q_domain = None
    self.q_record = None
    self.q_data = None
    self.tasks = []

  def GetPass(self, filename):
    f = open(filename) 
    for line in f.readlines():
      if line.startswith('requirepass') or line.startswith('pass'): 
        rp, password = line.strip().split(' ', 1)
        return password
    return None

  def ParseWithCommonArgs(self, argv, flaglist, arglist):
    al = arglist[:]
    al.extend(OPT_COMMON_ARGS)
    opts, args = getopt.getopt(argv, ''.join([OPT_COMMON_FLAGS, flaglist]), al)

    for opt, arg in opts:
      if opt in ('-R', '--redis'):
        self.redis_host, self.redis_port = arg.split(':')

      if opt in ('-A', '--auth'):
        self.redis_pass = self.GetPass(arg)        

      if opt in ('-z', '--reset'):
        self.q_record, self.q_data = None, None
        self.tasks = []

    return opts, args

  def ParseArgs(self, argv):
    opts, args = self.ParseWithCommonArgs(argv, OPT_FLAGS, OPT_ARGS)

    for opt, arg in opts:
      if opt in ('-D', '--domain'): self.q_domain = arg
      if opt in ('-r', '--record'): self.q_record = arg
      if opt in ('-d', '--data'): self.q_data = arg

      if opt in ('-q', '--query'):
        self.tasks.append(QueryOp(self,
                                  self.q_domain, self.q_record, self.q_data))

      if opt in ('-k', '--delete', '--kill'):
        self.tasks.append(DeleteOp(self,
                                   self.q_domain, self.q_record, self.q_data))

      if opt in ('-a', '--add'):
        self.tasks.append(AddOp(self,
                                self.q_domain, self.q_record, self.q_data, arg))

      if opt in ('-P', '--pdnsbe'):
        self.tasks.append(PdnsChatter(sys.stdin, sys.stdout, self))

    return self

  def BE(self):
    if not self.be:
      if self.redis_host == 'mock':
        self.be = MockRedis()
      else:
        self.be = redis.Redis(host=self.redis_host,
                              port=int(self.redis_port),
                              password=self.redis_pass)
      self.be.ping()
    return self.be

  def RunTasks(self):
    if not self.tasks:
      raise ArgumentError('Nothing to do!')
    else:
      self.BE()
      for task in self.tasks:
        print task.Run()


if __name__ == '__main__':
  try:
    pr = PdnsRedis().ParseArgs(sys.argv[1:]).RunTasks()
  except ArgumentError, e:
    print DOC
    print 'Error: %s' % e 
    sys.exit(1)

