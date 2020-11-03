<?php
namespace JoakimKejser\OAuth\SignatureMethod;

use JoakimKejser\OAuth\ConsumerInterface;
use JoakimKejser\OAuth\OAuthUtil;
use JoakimKejser\OAuth\SignatureMethod;
use JoakimKejser\OAuth\OauthRequest;
use JoakimKejser\OAuth\Consumer;
use JoakimKejser\OAuth\Token;
use JoakimKejser\OAuth\TokenInterface;
use Joakimkejser\OAuth\Util;

/**
 * The HMAC-SHA1 signature method uses the HMAC-SHA1 signature algorithm as defined in [RFC2104]
 * where the Signature Base String is the text and the key is the concatenated values (each first
 * encoded per Parameter Encoding) of the Consumer Secret and Token Secret, separated by an '&'
 * character (ASCII code 38) even if empty.
 *   - Chapter 9.2 ("HMAC-SHA1")
 */
class HmacSha1 extends SignatureMethod
{
    /**
     * @return string
     */
    public function getName()
    {
        return "HMAC-SHA1";
    }

    /**
     * @param OauthRequest $request
     * @param ConsumerInterface $consumer
     * @param TokenInterface $token
     * @return string
     */
    public function buildSignature(OauthRequest $request, ConsumerInterface $consumer, TokenInterface $token = null)
    {
        $baseString = $request->getSignatureBaseString();
        $request->setBaseString($baseString);

        $keyParts = array(
            $consumer->getSecret(),
            ($token) ? $token->getSecret() : ""
        );

        $keyParts = Util::urlencodeRfc3986($keyParts);
        $key = implode('&', $keyParts);

        return base64_encode(hash_hmac('sha1', $baseString, $key, true));
    }
}
