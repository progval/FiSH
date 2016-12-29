### 
# Copyright (c) 2016, megahambone
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions, and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions, and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of the author of this software nor the name of
#     contributors to this software may be used to endorse or promote products
#     derived from this software without specific prior written consent.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

###

import supybot.utils as utils
from supybot.commands import *
import supybot.plugins as plugins
import supybot.ircutils as ircutils
import supybot.callbacks as callbacks
import supybot.registry as registry
import supybot.ircmsgs as ircmsgs
import supybot.conf as conf
import supybot.ircdb as ircdb
import os
from Crypto.Util.strxor import strxor as xorstring
from Crypto.Cipher import Blowfish
import base64
import hashlib

import supybot.log as log

try:
    from supybot.i18n import PluginInternationalization
    _ = PluginInternationalization('Fish')
except ImportError:
    # Placeholder that allows to run the plugin on a bot
    # without the i18n module
    _ = lambda x: x


def registerDefaultPlugin(command, plugin): 
     command = callbacks.canonicalName(command) 
     conf.registerGlobalValue(conf.supybot.commands.defaultPlugins, 
                              command, registry.String(plugin, '')) 
     # This must be set, or the quotes won't be removed. 
     conf.supybot.commands.defaultPlugins.get(command).set(plugin) 


class Fish(callbacks.Privmsg):
    """Providing Fish Encryption."""
    threaded = True

    # I don't know it it makes sense to put keys in config, just because I don't want other things to access them
    # for now, I'm settling on leaving these blank on load and letting the operator configure it.
    _privkey = {}
    _password = None

    # called on load
    def __init__(self, irc):
        self.__parent = super(Fish, self)
        self.__parent.__init__(irc)
        # other initialization.
        if self.registryValue('disableSensitiveFunctions'):
        # if we should turn off the other functions...
            # disable cleartext identify
            anticap = ircdb.makeAntiCapability('user.identify')
            conf.supybot.capabilities().add(anticap)
            # disable cleartext register
            anticap = ircdb.makeAntiCapability('user.register')
            conf.supybot.capabilities().add(anticap)
            # if there's already a default set, unset them
            try: 
                conf.supybot.commands.defaultPlugins.unregister('identify') 
            except registry.NonExistentRegistryEntry:
                pass

            try: 
                conf.supybot.commands.defaultPlugins.unregister('register')
            except registry.NonExistentRegistryEntry:
                pass

            # and use ours instead.
            registerDefaultPlugin('identify', 'Fish')
            registerDefaultPlugin('register', 'Fish')

    def die(self):
        if self.registryValue('disableSensitiveFunctions'):
        # we should unbreak the functions.
            # back to normal
            conf.supybot.capabilities().add('user.identify')
            conf.supybot.capabilities().add('user.register')
            try: 
                conf.supybot.commands.defaultPlugins.unregister('identify') 
            except registry.NonExistentRegistryEntry:
                pass

            try: 
                conf.supybot.commands.defaultPlugins.unregister('register')
            except registry.NonExistentRegistryEntry:
                pass
            # back to normal
            registerDefaultPlugin('identify', 'User')
            registerDefaultPlugin('register', 'User')


    def outFilter(self, irc, msg):
        """
        Function fired on every outgoing message - if the encryption is on, here's where it gets applied.
        """

        # TODO need better filtering (PRIVMSG/NOTICE)

        # sure, in a better world, i'd do this different, but without this block, supybot throws a ton of errors during connect.
        try:
            b = msg.args[1]
        except IndexError:
            return msg

        if not msg.args[1].startswith('DH1080_FINISH'): # This message happens to confirm encryption. If we encrypt it, we never complete the handshake.
            if(msg.args[0] in self._privkey): # But, if it's any other message and if the channel/user is in the private key storage
                if self._privkey.get(msg.args[0])['encrypt'] == True: # And encryption for that channel/user is on
                    msg = ircmsgs.privmsg(msg.args[0], self._mircryption_cbc_pack(self._privkey.get(msg.args[0])['key'], msg.args[1]), msg=msg) # encrypt the message.
        return msg # and return it.

    def listCommands(self): # override the list. Maybe unnecessary, but I don't want people poking around with setpass and setkey.
        commands = ['getkey', 'encrypt', 'decrypt']
        return commands

    def _checkMessage(self, msg, encryptionrequired, pmrequired):
        retVal = True # assume it's a good message.
        if pmrequired and ircutils.isChannel(msg.args[0]):
            retVal = False # this isn't good.
        if encryptionrequired and not msg.encrypted:
            retVal = False # and this isn't good.
        return retVal

    def inFilter(self, irc, msg):
        """
        Function fires on every incoming message. to the bot. Here's where the bulk of it works.
        """

        # TODO need better filtering (PRIVMSG/NOTICE)

        # some of the messages from the connection process make the bot throw errors.
        try: # this seems to work (same as with outFilter - probably a better way to do this)
            b = msg.args[1]
        except IndexError:
            return msg
    
        target = None
    
        if msg.args[0] == conf.supybot.nick(): # if the "channel" is the bot's nick
            target = msg.nick # then the target is the sender.
        else:
            target = msg.args[0] # otherwise it's the channel.

        # TODO: Block cleartext sensitive functions here (register/identify)
        # need to find a good way to identify bot functions.
	
        # decryption:
        if msg.args[1].startswith('+OK'): # if it looks encrypted
            if target in self._privkey and self._privkey.get(target)['encrypt'] == True: # and this user has encryption on
                msg = ircmsgs.privmsg(msg.args[0], self._mircryption_cbc_unpack(self._privkey.get(target)['key'], msg.args[1]), msg=msg) # convert to cleartext for interpretation.
                msg.tag('encrypted') #and flag the message
            else: 
                if not target.startswith('#'): # if you're getting encrypted data from a private message and it can't be decoded, let the user know.
                    irc.queueMsg(ircmsgs.privmsg(msg.nick, "You're speaking gibberish to me. Resend a keyx so I can understand you.")) #done

        return msg

    def setpass(self, irc, msg, args, password):
        """<password>

        Sets the bot update password
        """
        # admin only, please.
        if not ircdb.checkCapability(msg.prefix, 'admin'):
            irc.errorNoCapability('admin')
            return

        if not self._checkMessage(msg, True, True): # if the message wasn't flagged as encrypted
            irc.reply("You've sent this insecurely. Open a private message, keyx the bot and try again. Clearing password for security.")
            self._password = None # let the user know, lock down the module
            return # and exit without processing

        self._password = password # set the password
        irc.reply("Key change password set. Please do not share.") # provide user status.
    setpass = wrap(setpass, ['text'])

    # wrapper for user.register with encryption validation
    def register(self, irc, msg, args, name, password):
        """<name> <password>

        Registers <name> with the given password <password> and the current
        hostmask of the person registering.  You shouldn't register twice; if
        you're not recognized as a user but you've already registered, use the
        hostmask add command to add another hostmask to your already-registered
        user, or use the identify command to identify just for a session.
        This command (and all other commands that include a password) must be
        sent to the bot privately, not in a channel.
        """
        if not self._checkMessage(msg, True, True):
            irc.reply("When FiSH is loaded, users can't register plaintext. Sorry")
            return

        cb = irc.getCallback('User')
        cb.register(irc, msg, [name, password])

    register = wrap(register, ['private', 'something', 'something'])
    
    # wrapper for user.identify with encryption validation
    def identify(self, irc, msg, args, user, password):
        """<name> <password>

        Identifies the user as <name>. This command (and all other
        commands that include a password) must be sent to the bot privately,
        not in a channel.
        """
        if not self._checkMessage(msg, True, True):
            irc.reply("When FiSH is loaded, users can't identify plaintext. Sorry")
            return

        cb = irc.getCallback('User')
        cb.identify(irc, msg, [user, password])

    identify = wrap(identify, ['private', 'something', 'something'])
    
    def setkey(self, irc, msg, args, channel, password, privkey):
        """<channel> <password> <privkey>

        Sets a key for a channel.
        """
        if self._password == None: # if the password is blank
            irc.reply("FiSH module locked down due to password being set publically or in cleartext. Have an Admin set a new password.")
            return # tell the user what to do and bail.

        if not self._checkMessage(msg, True, True): #if the message wasn't flagged as encrypted
            irc.reply("You've sent this insecurely. Open a private message, keyx the bot and try again. Clearing password for security.")
            self._password = None # let the user know, lock down the module
            return # and exit without processing.

        if password == self._password: # otherwise, if they've provided the right password, add the key to the list.
            entry = {'key': privkey, 'encrypt': False} # encryption off by default
            self._privkey[channel] = entry
            irc.reply("Key set for channel.")
    setkey = wrap(setkey, ['channel', 'something', 'something'])
 
    def getkey(self, irc, msg, args, channel):
        """<channel>

        Gets a key for a channel
        """
        # remember that the bot will only fire this command if it's sent via encryption.
        # check if not in pm and handle appropriately.
        #if not msg.args[0] == conf.supybot.nick():
        #    irc.reply("You can't get the key in public. Send me a keyx in pm and try again!")
        #    return # and shame the user publically a bit.

        if not self._checkMessage(msg, True, True): # if the message isn't flagged
            irc.reply("You've sent this insecurely. Open a private message, keyx the bot and try again.")
            return # tell them without locking the module, this isn't a security issue.

        # otherwise, send the key
        if not channel in self._privkey:
            irc.reply("I dont have a key for %s. Get an admin to set the key" % channel)
        else:
            irc.reply("the key is %s" % self._privkey[channel]['key'], private=True)
    getkey = wrap(getkey, ['channel'])

    def encrypt(self, irc, msg, args, channel):
        """
        Turns on encryption
        """
        if not channel in self._privkey:
            irc.reply("I don't have a key for %s. Get an admin to set the key" % channel)
        else: # turn on the encryption flag.
            self._privkey[channel]['encrypt'] = True
            irc.replySuccess()
    encrypt = wrap(encrypt, ['channel'])

    def decrypt(self, irc, msg, args, channel):
        """
        Turn off encryption
        """
        if not channel in self._privkey:
            return
        else:
            self._privkey[channel]['encrypt'] = False # turn off the encryption flag.
            irc.replySuccess()
    decrypt = wrap(decrypt, ['channel'])


    def doNotice(self, irc, msg):
        if msg.args[1].startswith('DH1080_INIT'): # if someone does a keyx
            self._dh1080_init(irc, msg.nick, msg.args[1]) # initialize the keyx process.
            return


    # most of this code was inspired by or straight up cribbed from here:
    # https://github.com/kwaaak/py-fishcrypt
    def _dh1080_init(self, irc, target, payload):
        dh = DH1080Ctx()
        dh1080_unpack(payload, dh)
    
        key = dh1080_secret(dh)
        keyname = target
        encrypt = True
    
        entry = {'key': key, 'encrypt': encrypt} 

        self._privkey[keyname] = entry

        irc.sendMsg(ircmsgs.notice(target, dh1080_pack(dh)))

    def _mircryption_cbc_pack(self, hash, text):
        bf = Blowfish.new(hash)
        padded = self._padto(text, 8)
        return '+OK *%s' % (base64.b64encode(self._cbc_encrypt(bf.encrypt, padded, 8)))    

    def _mircryption_cbc_unpack(self, hash, text):
        bf = Blowfish.new(hash)
        if not (text.startswith('+OK *') or text.startswith('mcps *')):
            raise ValueError

        try:
            _, coded = text.split('*', 1)
            raw = base64.b64decode(coded)
        except TypeError:
            raise MalformedError
        if not raw:
            raise MalformedError

        try:
            padded = self._cbc_decrypt(bf.decrypt, raw, 8)
        except ValueError:
            raise MalformedError
        if not padded:
            raise MalformedError

        return padded.strip('\x00')        

    def _padto(self, text, length):
        """Pads 'msg' with zeroes until it's length is divisible by 'length'.
        If the length of msg is already a multiple of 'length', does nothing."""
        L = len(text)
        if L % length:
            text = "%s%s" % (text,'\x00' * (length - L % length))
        assert len(text) % length == 0
        return text

    def _cbc_encrypt(self, func, data, blocksize):
        """The CBC mode. The randomy generated IV is prefixed to the ciphertext.
        'func' is a function that encrypts data in ECB mode. 'data' is the
        plaintext. 'blocksize' is the block size of the cipher."""
        assert len(data) % blocksize == 0
    
        IV = os.urandom(blocksize)
        assert len(IV) == blocksize
    
        ciphertext = IV
        for block_index in xrange(len(data) / blocksize):
            xored = xorstring(data[:blocksize], IV)
            enc = func(xored)
        
            ciphertext += enc
            IV = enc
            data = data[blocksize:]

        assert len(ciphertext) % blocksize == 0
        return ciphertext


    def _cbc_decrypt(self, func, data, blocksize):
        """See cbc_encrypt."""
        assert len(data) % blocksize == 0
    
        IV = data[0:blocksize]
        data = data[blocksize:]

        plaintext = ''
        for block_index in xrange(len(data) / blocksize):
            temp = func(data[0:blocksize])
            temp2 = xorstring(temp, IV)
            plaintext += temp2
            IV = data[0:blocksize]
            data = data[blocksize:]
    
        assert len(plaintext) % blocksize == 0
        return plaintext


Class = Fish

# DH1080 support functions.
# also cribbed from https://github.com/kwaaak/py-fishcrypt

def bytes2int(b):
    """Variable length big endian to integer."""
    n = 0
    for p in b:
        n *= 256
        n += ord(p)
    return n

def sha256(s):
    """sha256"""
    return hashlib.sha256(s).digest()

def int2bytes(n):
    """Integer to variable length big endian."""
    if n == 0:
        return '\x00'
    b = []
    while n:
        b.insert(0,chr(n % 256))
        n /= 256
    return "".join(b)


g_dh1080 = 2
p_dh1080 = int('FBE1022E23D213E8ACFA9AE8B9DFAD'
               'A3EA6B7AC7A7B7E95AB5EB2DF85892'
               '1FEADE95E6AC7BE7DE6ADBAB8A783E'
               '7AF7A7FA6A2B7BEB1E72EAE2B72F9F'
               'A2BFB2A2EFBEFAC868BADB3E828FA8'
               'BADFADA3E4CC1BE7E8AFE85E9698A7'
               '83EB68FA07A77AB6AD7BEB618ACF9C'
               'A2897EB28A6189EFA07AB99A8A7FA9'
               'AE299EFA7BA66DEAFEFBEFBF0B7D8B', 16)
q_dh1080 = (p_dh1080 - 1) / 2 

def dh1080_b64encode(s):
    """A non-standard base64-encode."""
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    d = [0]*len(s)*2

    L = len(s) * 8
    m = 0x80
    i, j, k, t = 0, 0, 0, 0
    while i < L:
        if ord(s[i >> 3]) & m:
            t |= 1
        j += 1
        m >>= 1
        if not m:
            m = 0x80
        if not j % 6:
            d[k] = b64[t]
            t &= 0
            k += 1
        t <<= 1
        t %= 0x100
        #
        i += 1
    m = 5 - j % 6
    t <<= m
    t %= 0x100
    if m:
        d[k] = b64[t]
        k += 1
    d[k] = 0
    res = []
    for q in d:
        if q == 0:
            break
        res.append(q)
    return "".join(res)

def dh1080_b64decode(s):
    """A non-standard base64-encode."""
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    buf = [0]*256
    for i in range(64):
        buf[ord(b64[i])] = i

    L = len(s)
    if L < 2:
        raise ValueError
    for i in reversed(range(L-1)):
        if buf[ord(s[i])] == 0:
            L -= 1
        else:
            break
    if L < 2:
        raise ValueError

    d = [0]*L
    i, k = 0, 0
    while True:
        i += 1
        if k + 1 < L:
            d[i-1] = buf[ord(s[k])] << 2
            d[i-1] %= 0x100
        else:
            break
        k += 1
        if k < L:
            d[i-1] |= buf[ord(s[k])] >> 4
        else:
            break
        i += 1
        if k + 1 < L:
            d[i-1] = buf[ord(s[k])] << 4
            d[i-1] %= 0x100
        else:
            break
        k += 1
        if k < L:
            d[i-1] |= buf[ord(s[k])] >> 2
        else:
            break
        i += 1
        if k + 1 < L:
            d[i-1] = buf[ord(s[k])] << 6
            d[i-1] %= 0x100
        else:
            break
        k += 1
        if k < L:
            d[i-1] |= buf[ord(s[k])] % 0x100
        else:
            break
        k += 1
    return ''.join(map(chr, d[0:i-1]))


def dh_validate_public(public, q, p):
    """See RFC 2631 section 2.1.5."""
    return 1 == pow(public, q, p)


class DH1080Ctx:
    """DH1080 context."""
    def __init__(self):
        self.public = 0
        self.private = 0
        self.secret = 0
        self.state = 0
        
        bits = 1080
        while True:
            self.private = bytes2int(os.urandom(bits/8))
            self.public = pow(g_dh1080, self.private, p_dh1080)
            if 2 <= self.public <= p_dh1080 - 1 and \
               dh_validate_public(self.public, q_dh1080, p_dh1080) == 1:
                break

def dh1080_pack(ctx):
    """."""
    if ctx.state == 0:
        ctx.state = 1
        cmd = "DH1080_INIT"
    else:
        cmd = "DH1080_FINISH"
    return "%s %s" % (cmd,dh1080_b64encode(int2bytes(ctx.public)))

def dh1080_unpack(msg, ctx):
    """."""
    if not "DH1080_" in msg:
        raise ValueError

    invalidmsg = "Key does not validate per RFC 2631. This check is not performed by any DH1080 implementation, so we use the key anyway. See RFC 2785 for more details."

    if ctx.state == 0:
        if not "DH1080_INIT " in msg:
            raise MalformedError
        ctx.state = 1
        try:
            cmd, public_raw = msg.split(' ', 1)
            public = bytes2int(dh1080_b64decode(public_raw))

            if not 1 < public < p_dh1080:
                raise MalformedError
            
            if not dh_validate_public(public, q_dh1080, p_dh1080):
                pass
                
            ctx.secret = pow(public, ctx.private, p_dh1080)
        except:
            raise MalformedError

    elif ctx.state == 1:
        if not "DH1080_FINISH " in msg:
            raise MalformedError
        ctx.state = 1
        try:
            cmd, public_raw = msg.split(' ', 1)
            public = bytes2int(dh1080_b64decode(public_raw))

            if not 1 < public < p_dh1080:
                raise MalformedError

            if not dh_validate_public(public, q_dh1080, p_dh1080):
                pass
            
            ctx.secret = pow(public, ctx.private, p_dh1080)
        except:
            raise MalformedError

    return True
        

def dh1080_secret(ctx):
    """."""
    if ctx.secret == 0:
        raise ValueError
    return dh1080_b64encode(sha256(int2bytes(ctx.secret)))



# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

