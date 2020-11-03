<?php
namespace JoakimKejser\OAuth;

/**
 * Interface TokenInterface.
 */
interface TokenInterface
{
	/**
	 * @return string
	 */
	public function getKey();

	/**
	 * @return string
	 */
	public function getSecret();

//        return "oauth_token=" .
//        Util::urlencodeRfc3986($this->key) .
//        "&oauth_token_secret=" .
//        Util::urlencodeRfc3986($this->secret);
}
