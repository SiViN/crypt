# crypt
Small library for encryption via [phpseclib](https://github.com/phpseclib/phpseclib)

[![Build Status](https://travis-ci.org/SiViN/crypt.svg?branch=master)](https://travis-ci.org/SiViN/crypt)
[![License](https://poser.pugx.org/sivin/crypt/license)](https://packagist.org/packages/sivin/crypt)
[![Total Downloads](https://poser.pugx.org/sivin/crypt/downloads)](https://packagist.org/packages/sivin/crypt)

1. Install via composer
	```yaml
	composer require sivin/crypt
	```

2. Register extension in `config.neon`:
	```php
	extensions:
		crypt: SiViN\Crypt\DI\CryptExtension
	```

3. Create or use your key/s:
	```php
	/** @var Crypt */
	private $crypt;

	public function __construct(Crypt $crypt)
	{
		$this->crypt = $crypt;
	}
	...
	$keys = $this->crypt->createKeyPair()
	$privateKeyRaw = $keys['privateKeyRaw'];
	$publicKeyRaw = $keys['publicKeyRaw'];
	```

4. Use your own key or define it in a `config.local.neon`:
	```php
	$crypt->setPublicKey($myPublicKeyForEncrypt);
	$crypt->setPrivateKey($myPrivateKeyForDecrypt);
	//if there is a private key with a password
	$crypt->setPrivateKeyPassword($myPivateKeyPasswordForDecrypt);
	```
	
	or in a `config.local.neon`:
	
	```php
	crypt:
		publicKeyPath: publicKeyFile.pub #for encrypting
		privateKeyPath: privateKeyFile.key #for decrypting
		privateKeyPassword: 'PrivateKeyPassword' #optional
	```
	>If you only want to encrypt/decrypt, just define the encrypting/decrypting key
	
5. And finally?:	
	```php
	$encryptedStr = $crypt->encryptRijndaelMessage($stringToEncode); //for transport
	$decryptedStr = $crypt->decryptRijndaelMessage($encryptedStr);

	$encryptedStr = $crypt->encryptRsa($stringToEncode);
	$decryptedStr = $crypt->decryptRsa($encryptedStr);

	$encryptedStr = $crypt->encryptRijndael($stringToEncode);
	$decryptedStr = $crypt->decryptRijndael($encryptedStr);
	```
	

