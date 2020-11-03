<?php
namespace JoakimKejser\OAuth;

/**
 * Class AccessToken
 * @package JoakimKejser\OAuth
 */
class RequestToken implements TokenInterface
{
    /**
     * @var
     */
    protected $key;

    /**
     * @var
     */
    protected $secret;

    /**
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }
}
