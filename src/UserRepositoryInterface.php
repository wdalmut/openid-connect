<?php
namespace Corley\OpenId;

use League\OAuth2\Server\Repositories\UserRepositoryInterface as Repo;

interface UserRepositoryInterface extends Repo
{
    /**
     * @return League\OpenIdConnectClaims\ClaimsSet
     */
    public function getUserClaimsByUserId($userId, array $scopes = []);
}
