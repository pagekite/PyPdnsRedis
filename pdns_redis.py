#!/usr/bin/python
#
# pdns-redis.py, Copyright 2011, Bjarni R. Einarsson <http://bre.klaki.net/>
#                                and The Beanstalks Project ehf.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
BANNER = "pdns-redis.py, by Bjarni R. Einarsson"
DOC = """\
pdns-redis.py is Copyright 2012, Bjarni R. Einarsson, http://bre.klaki.net/
                                 and The Beanstalks Project ehf.

This program implements a PowerDNS pipe-backend for looking up domain info in a
Redis database.  It also includes basic CLI functionality for querying, setting
and deleting DNS records in Redis.

Usage: pdns-redis.py [-R <host:port>] [-A <password-file>] [-P]
       pdns-redis.py [-R <host:port>] [-A <password-file>]
                     [-D <domain>] [-r <type>] [-d <data>] [-k] [-q] [-a <ttl>]

Flags:

  -R <host:port>     Set the Redis back-end.
  -W <host:port>     Set the Redis back-end for writes.
  -A <password-file> Read a Redis password from the named file.
  -P                 Run as a PowerDNS pipe-backend.
  -w                 Enable wild-card lookups in PowerDNS pipe-backend.
  -D <domain>        Select a domain for -q or -a.
  -r <record-type>   Choose which record to modify/query/delete.
  -d <data>          Data we are looking for or adding.
  -z                 Reset record and data.
  -q                 Query.
  -k                 Kill (delete).
  -a <ttl>           Add using a given TTL (requires -r and -d).  The TTL
                     is in seconds, but may use a suffix of M, H, D or W
                     for minutes, hours, days or weeks respectively.

WARNING: This program does NOTHING to ensure the records you create are valid
         according to the DNS spec.  Use at your own risk!

Queries and kills (deletions) are filtered by -r and -d, if present.  If
neither is specified, the entire domain is processed.

Note that arguments are processed in order so multiple adds and deletes can
be done at once, just by repeating the -D, -r, -d, -k and -a arguments, varying
the data as you go along.

Domain entries starting with a '*', for example *.foo.com, will be treated as
wild-card entries by the PowerDNS pipe-backend, if the -w flag precedes -P.

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
  pdns-redis.py -R localhost:9076 -w -P  # Now with wildcard domains!

"""

import getopt
import hashlib
import random
import re
import redis
import socket
import sys
import syslog
import time
import urllib

DEBUG = False

OPT_COMMON_FLAGS = 'A:R:W:z'
OPT_COMMON_ARGS = ['auth=', 'redis=', 'redis_write=', 'reset']
OPT_FLAGS = 'PwD:r:d:kqa:'
OPT_ARGS = ['pdnsbe', 'domain', 'record', 'data', 'kill', 'delete', 'query',
            'add']

VALID_RECORDS = ['A', 'AAAA', 'NS', 'MX', 'CNAME', 'SOA', 'TXT']
TTL_SUFFIXES = {
  'M': 60,
  'H': 60*60,
  'D': 60*60*24,
  'W': 60*60*24*7,
}
MAGIC_SELF_IP = 'self'
MAGIC_TEST_VALIDITY = 60 # seconds

REDIS_PREFIX = 'pdns.'


class MockRedis(object):
  """A mock-redis object for quick offline tests."""
  def __init__(self, host=None, port=None, password=None):
    self.data = {}
  def ping(self): return True
  def get(self, key):
    if key in self.data: return self.data[key]
    return None
  def encode(self, val):
    if isinstance(val, str):
      return val
    if isinstance(val, unicode):
      return val.encode('utf-8')
    return str(val)
  def set(self, key, val):
    self.data[key] = self.encode(val)
    return True
  def setnx(self, key, val):
    if key in self.data: return None
    self.data[key] = self.encode(val)
    return val
  def incr(self, key):
    if key not in self.data: self.data[key] = 0
    self.data[key] = self.encode(int(self.data[key])+1)
    return int(self.data[key])
  def incrby(self, key, val):
    if key not in self.data: self.data[key] = 0
    self.data[key] = self.encode(int(self.data[key])+int(val))
    return int(self.data[key])
  def delete(self, key):
    if key in self.data:
      del(self.data[key])
      return True
    else:
      return False
  def hget(self, key, hkey):
    if key in self.data and hkey in self.data[key]: return self.data[key][hkey]
    return None
  def hincrby(self, key, hkey, val):
    if key not in self.data: self.data[key] = {}
    if hkey not in self.data[key]: self.data[key][hkey] = 0
    self.data[key][hkey] = self.encode(int(self.data[key][hkey])+int(val))
    return int(self.data[key][hkey])
  def hgetall(self, key):
    if key in self.data: return self.data[key]
    return {}
  def hdel(self, key, hkey):
    if key in self.data and hkey in self.data[key]: del(self.data[key][hkey])
    return True
  def hset(self, key, hkey, val):
    if key not in self.data: self.data[key] = {}
    self.data[key][hkey] = self.encode(val)
    return True
  def sadd(self, key, member):
    if key not in self.data: self.data[key] = {}
    self.data[key][member] = 1
    return True
  def srem(self, key, member):
    if key in self.data and member in self.data[key]:
      del self.data[key][member]
      return True
    return False
  def lpush(self, key, value):
    if key not in self.data:
      self.data[key] = []
    self.data[key].append(value)
    return True
  def llen(self, key):
    if key not in self.data: return 0
    return len(self.data[key])
  def lpop(self, key):
    return self.data[key].pop(0)


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

  def BE(self):
    return self.redis_pdns.BE()

  def DSplit(self, domain, count=1024):
    return domain.split('.', count)

  def WildQuery(self, domain):
    try:
      sub, dom = self.DSplit(domain, 1)
      if sub == '*':
        sub, dom = self.DSplit(dom, 1)
      return self.Query(domain='*.%s' % dom)
    except ValueError:
      return []

  def _Query(self, domain=None, wildcards=False):
    pdns_be = self.BE()
    pdns_key = REDIS_PREFIX+(domain or self.domain)

    if self.record and self.data:
      key = "\t".join([self.record, self.data])
      ttl = pdns_be.hget(pdns_key, key)
      if ttl is not None:
        pdns_be.hincrby(pdns_key, 'TXT\tQC', 1)
        return [(self.domain, self.record, ttl, self.data)]
      elif wildcards:
        return self.WildQuery(domain or self.domain)
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

    if rv:
      pdns_be.hincrby(pdns_key, 'TXT\tQC', 1)
      return rv
    elif wildcards:
      return self.WildQuery(domain or self.domain)
    else:
      return []

  def Query(self, *args, **kwargs):
    try:
      return self._Query(*args, **kwargs)
    except redis.RedisError:
      self.redis_pdns.Disconnect()
      raise

  def Run(self):
    return '%s' % (self.Query(), )


class WriteOp(QueryOp):
  def BE(self):
    return self.redis_pdns.WBE()


class DeleteOp(WriteOp):
  """This object will delete records from Redis."""

  def Run(self):
    if not self.record and not self.data:
      self.BE().delete(REDIS_PREFIX+self.domain)
      return 'Deleted all records for %s.' % self.domain

    deleted = 0
    if self.record and self.data:
      deleted += self.BE().hdel(REDIS_PREFIX+self.domain,
                                "\t".join([self.record, self.data]))
    else:
      for record in self.Query():
        deleted += self.BE().hdel(REDIS_PREFIX+self.domain,
                                  "\t".join([record[1], record[3]]))

    return 'Deleted %d records from %s.' % (deleted, self.domain)


class AddOp(WriteOp):
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
    self.BE().hset(REDIS_PREFIX+self.domain,
                   "\t".join([self.record, self.data]), self.ttl)
    return 'Added %s record to %s.' % (self.record, self.domain)


class PdnsChatter(Task):
  """This object will chat with the pDNS server."""

  def __init__(self, infile, outfile, redis_pdns,
               query_op=None, wildcards=False):
    self.infile = infile
    self.outfile = outfile
    self.query_count = 0
    self.redis_pdns = redis_pdns
    self.local_ip = None
    self.magic_tests = {}
    self.qop = query_op or QueryOp
    self.wildcards = wildcards
    self.log_buffer = []
    syslog.openlog((sys.argv[0] or 'pdns_redis.py').split('/')[-1],
                    syslog.LOG_PID, syslog.LOG_DAEMON)

  def reply(self, text):
    self.outfile.write(text)
    self.outfile.write("\n")
    self.outfile.flush()

  def readline(self):
    line = self.infile.readline()
    if len(line) == 0: raise IOError('EOF')
    return line.strip()

  def SendMxOrSrv(self, d1, d2, d3, d4):
    self.reply('DATA\t%s\tIN\t%s\t%s\t-1\t%s' % (d1, d2, d3, d4))

  def MagicTest(self, want, url, now=None):
    now = now or time.time()
    result = self.magic_tests.get(url, {})

    if result.get('time', 0) < (now - MAGIC_TEST_VALIDITY):
      result['time'] = now
      try:
        tdata = ''.join(urllib.urlopen(url).readlines())
        result['ok'] = tdata.startswith(want)
      except:
        result['ok'] = False

    self.magic_tests[url] = result
    if not result.get('ok', False):
      raise ValueError('Failed self-test %s != %s' % (want, url))

  def ResponseFilter(self, name, rt, ttl, val):
    return name, rt, ttl, val

  def SendRecord(self, record, remote_ip=None):
    if not remote_ip:
      remote_ip = '127.%d.%d.1' % (random.randint(1, 255),
                                   random.randint(1, 255))

    if record[3].startswith(MAGIC_SELF_IP):
      if ':' in record[3]:
        magic, test_want, test_url = record[3].split(':', 2)
        self.MagicTest(want, test_url)

      if not self.local_ip:
        raise ValueError("Local IP address is unknown")
      self.reply('DATA\t%s\tIN\t%s\t%s\t-1\t%s' % self.ResponseFilter(
        record[0], record[1], record[2], self.local_ip))

    elif record[1] not in ('A', 'AAAA'):
      self.reply('DATA\t%s\tIN\t%s\t%s\t-1\t%s' % self.ResponseFilter(
        record[0], record[1], record[2], record[3]))

    elif remote_ip and '/' in record[3]:
      # The goal of this, is to hash different clients to different IPs,
      # and rotate through the available set at 1 rotation-per-day, but
      # avoid rotating all the clients at the same time.
      values = record[3].split('/')
      o = int((time.time() +
               # Hash the first 3 octets of the IP to 5 hex digits; this
               # gives us 0-12 days of offset to shift the time by.
               int(hashlib.md5(remote_ip.rsplit('.', 1)[0]).hexdigest()[:5], 16)
               ) // (24 * 3600)
              ) % len(values)
      self.reply('DATA\t%s\tIN\t%s\t%s\t-1\t%s' % self.ResponseFilter(
        record[0], record[1], record[2], values[o]))

    else:
      value = random.choice(record[3].split('|'))
      self.reply('DATA\t%s\tIN\t%s\t%s\t-1\t%s' % self.ResponseFilter(
        record[0], record[1], record[2], value))

  def FlushLogBuffer(self):
    lb, self.log_buffer = self.log_buffer, []
    for message in lb:
      self.reply('LOG\t%s' % message)

  def SendLog(self, message):
    self.log_buffer.append(message)

  def EndReply(self):
    self.FlushLogBuffer()
    self.reply('END')

  def SetLocalIp(self, value):
    if not (value == '0.0.0.0' or
            value.startswith('127.') or
            value.startswith('192.168.') or
            value.startswith('10.')):
      self.local_ip = value

  def SlowGetOwnIp(self, target=('google.com', 80)):
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.connect(target)
      self.SetLocalIp(s.getsockname()[0])
      s.close()
    except:
      pass

  SRV_SPLIT = re.compile('[\\s,]+')

  def Lookup(self, query):
    (pdns_qtype, domain, qclass, rtype, _id, remote_ip, local_ip) = query

    if not self.local_ip:
      self.SetLocalIp(local_ip)
      if not self.local_ip:
        try:
          self.SetLocalIp(socket.getaddrinfo(socket.gethostname(), None)[0][4][0])
        except:
          pass

    if pdns_qtype == 'Q':
      if not domain:
        records = []
      elif rtype == 'ANY':
        records = self.qop(self.redis_pdns, domain
                           ).Query(wildcards=self.wildcards)
      else:
        records = self.qop(self.redis_pdns, domain, rtype
                           ).Query(wildcards=self.wildcards)

      for record in records:
        if record[1] in ('MX', 'SRV'):
          data = '\t'.join(self.SRV_SPLIT.split(record[3], 1))
          self.SendMxOrSrv(record[0], record[1], record[2], data)
        elif record[1] != 'TXT' or record[3] != 'QC':
          self.SendRecord(record, remote_ip)

      self.EndReply()
    else:
      self.SendLog("PowerDNS requested %s, we only do Q." % pdns_qtype)
      self.FlushLogBuffer()
      self.reply('FAIL')

  def KeepRunning(self):
    return True

  def Run(self):
    line1 = self.readline()
    if not line1 == "HELO\t2":
      self.reply('FAIL')
      self.readline()
      sys.exit(1)
    else:
      self.reply('OK\t%s' % BANNER)

    if not self.local_ip:
      self.SlowGetOwnIp()

    while self.KeepRunning():
      line = self.readline()
      if line == '':
        break
      try:
        query = line.split("\t")
        if DEBUG: syslog.syslog(syslog.LOG_DEBUG, 'Q: %s' % query)
        if len(query) == 7:
          self.Lookup(query)
          self.query_count += 1
        elif len(query) == 2 and query[0] == 'AXFR':
          # Just fail silently on this one
          self.reply("FAIL")
        else:
          self.FlushLogBuffer()
          self.reply("LOG\tPowerDNS sent bad request: %s" % query)
          self.reply("FAIL")
      except Exception, err:
        self.redis_pdns.Disconnect()
        self.FlushLogBuffer()
        self.reply("LOG\tInternal Error: %s" % err)
        self.reply("FAIL")


class PdnsRedis(object):
  """Main loop..."""

  def __init__(self):
    self.redis_host = None
    self.redis_port = None
    self.redis_pass = None
    self.redis_write_host = None
    self.redis_write_port = None
    self.be = None
    self.wbe = None
    self.chat_wildcards = False
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

      if opt in ('-W', '--redis_write'):
        self.redis_write_host, self.redis_write_port = arg.split(':')

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

      if opt in ('-w', ):
        self.chat_wildcards = True

      if opt in ('-P', '--pdnsbe'):
        self.tasks.append(PdnsChatter(sys.stdin, sys.stdout, self,
                                      wildcards=self.chat_wildcards))

    return self

  def Disconnect(self):
    self.be = self.wbe = None

  def BE(self):
    errors = 0
    while not self.be:
      try:
        if self.redis_host == 'mock':
          self.be = MockRedis()
        else:
          self.be = redis.Redis(host=self.redis_host,
                                port=int(self.redis_port),
                                password=self.redis_pass)
        self.be.ping()
      except redis.RedisError:
        self.be = None
        errors += 1
        if errors > 24:
          raise
        else:
          time.sleep(5)
    return self.be

  def WBE(self):
    if not self.redis_write_host: return self.BE()
    errors = 0
    while not self.wbe:
      try:
        if self.redis_write_host == 'mock':
          self.wbe = MockRedis()
        else:
          self.wbe = redis.Redis(host=self.redis_write_host,
                                 port=int(self.redis_write_port),
                                 password=self.redis_pass)
        self.wbe.ping()
      except redis.RedisError:
        self.wbe = None
        errors += 1
        if errors > 24:
          raise
        else:
          time.sleep(5)
    return self.wbe

  def RunTasks(self):
    if not self.tasks:
      raise ArgumentError('Nothing to do!')
    else:
      self.BE()
      for task in self.tasks:
        sys.stdout.write(task.Run().encode('utf-8')+'\n')


if __name__ == '__main__':
  try:
    pr = PdnsRedis().ParseArgs(sys.argv[1:]).RunTasks()
  except ArgumentError, e:
    print DOC
    print 'Error: %s' % e
    sys.exit(1)

