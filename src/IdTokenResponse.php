<?php
namespace Corley\OpenId;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;

use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Builder;

use Corley\OpenId\UserRepositoryInterface;

class IdTokenResponse extends BearerTokenResponse
{
    private $issuer;
    private $userRepository;

    public function __construct($issuer, UserRepositoryInterface $userRepository) {
        $this->issuer = $issuer;
        $this->userRepository = $userRepository;
    }

    public function getIssuer()
    {
        return $this->issuer;
    }

    public function getUserRepository()
    {
        return $this->userRepository;
    }

    /**
     * @param AccessTokenEntityInterface $accessToken
     * @return array
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken)
    {
        if (false === $this->isOpenIDRequest($accessToken->getScopes())) {
            return [];
        }

        // Add required id_token claims
        $builder = (new Builder())
            ->setAudience($accessToken->getClient()->getIdentifier())
            ->setId($accessToken->getIdentifier(), true)
            ->setIssuedAt(time())
            ->setNotBefore(time())
            ->setExpiration($accessToken->getExpiryDateTime()->getTimestamp())
            ->set('scopes', $accessToken->getScopes())
            ->setAudience($accessToken->getClient()->getIdentifier())
            ->setIssuer($this->getIssuer())
            ->setSubject($accessToken->getUserIdentifier());

        $userClaims = $this->getUserRepository()
            ->getUserClaimsByUserId($accessToken->getUserIdentifier(), $accessToken->getScopes())
            ->jsonSerialize();

        foreach ($userClaims as $claimKey => $claimValue) {
            $builder->set($claimKey, $claimValue);
        }

        $token = $builder
            ->sign(new Sha256(), new Key($this->privateKey->getKeyPath(), $this->privateKey->getPassPhrase()))
            ->getToken();

        return [
            'id_token' => (string) $token
        ];
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     * @return bool
     */
    private function isOpenIDRequest($scopes)
    {
        // Verify scope and make sure openid exists.
        $valid  = false;

        foreach ($scopes as $scope) {
            if ($scope->getIdentifier() === 'openid') {
                $valid = true;
                break;
            }
        }

        return $valid;
    }

}
