This plugin is designed to make a supybot/limnoria bot capable of running in FiSH CBC (mircryption) style channels.

It was designed as a fun project/experiment, with all of the DH1080 implementation borrowed lovingly from the following repo:
https://github.com/kwaaak/py-fishcrypt

The rest was done with the supybot template, much trial and error, facepalming and channel spamming.

If you use it and you like it, I'd love some feedback or maybe a cup of coffee/beer
BTC: 1CW1q1ABgkNZvQDuUjzDcDNZBvvkgd1fGA

to install, run:
pip install -r requirements.txt

Suggested workflow for best security:
(in a pm to your bot, enter the following commands)
load fish
defaultcapability remove fish.setkey
defaultcapability remove fish.getkey
defaultcapability remove fish.encrypt
defaultcapability remove fish.decrypt

Now that the module is loaded, your bot is capable of accepting keyexchanges. Send a keyexchange to your bot to turn on encryption and send the following commands:
setpass <your password here> (ex: setpass key_change_password)
setkey <channel> <password> <encryption key> (ex: setkey #cryptochannel key_change_password COMPLICATEDKEY)
encrypt <channel> to set the bot into FiSH CBC (mircryption) mode (ex: encrypt #cryptochannel)
at this point, set your channel encryption in your irc client of choice and you and your bot should have a nice private conversation.

Please note that the setpass and setkey functions can not be used without secure PM. If they don't work, double-check your client settings and ensure that you've properly sent a keyx to your bot.

To share the key securely with other users, I suggest having them register on your bot and setting the fish.getkey capability for them. This will safely allow your bot to distribute the encryption key to trusted users.

Module Notes:
When the Fish module is loaded, the commands "identify" or "register" will no longer be allowed in plaintext.
You may have to play with your supybot.reply.mores.length (I use 280) to account for the extra characters added in the encryption process.
As a neat side effect, if your bot is also a relay bot, the relay also becomes encrypted with the same key.

Function Reference:
setpass <password> (hidden from list fish)
What it does: Sets the key-changing password.
Who can use it: Restricted to admins only.
Notes: this command can only be run via secure message to the bot. 
       this command is hidden from 'list fish'

setkey <channel> <password> <encryption key>
What it does: Sets the channel key to a specific encryption key.
Who can use it: admins or anyone with fish.setkey capability
Notes: this command does not turn on encryption automatically.
       this command can only be run via secure message to the bot.
       this command is hidden from 'list fish'

getkey <channel>
What it does: Gets the channel key
Who can use it: admins or anyone with fish.getkey capability
Notes: this command can only be run via secure message to the bot.

encrypt <channel>
What it does: turns on encryption for the current channel (if not specified) or for a specific channel
Who can use it: admins or anyone with fish.encrypt capability
Notes: The bot will still "understand" cleartext triggers in encrypted mode, but all bot output is encrypted.

decrypt <channel>
What it does: turns off decryption for the current channel (if not specified) or for a specific channel
Who can use it: admins or anyone with fish.decrypt capability
Notes: None



