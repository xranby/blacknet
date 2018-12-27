
const Blacknet = angular.module('blacknet', ['ngResource'], function ($httpProvider) {
    $httpProvider.interceptors.push(function ($q) {
        return {
            'response': function (response) {

                if (typeof response.data == 'string') {
                    response.data = {
                        text: response.data
                    }
                }

                return response;
            }
        };
    });
})
const apiVersion = "/api/v1";
Blacknet
    
    .factory('Ledger', function ($resource) {
        return $resource(apiVersion + '/ledger', {}, {
            getBalance: {
                url: apiVersion + '/ledger/get/:account/',
                method: 'get',
                params: { account: '@account' }
            },
            queryBlock: {
                url: apiVersion + '/blockdb/get/:hash',
                method: 'get',
                params: { hash: '@hash' }
            },
            peerInfo: {
                url: apiVersion + '/peerinfo',
                isArray: true
            },
            peerDB: {
                url: apiVersion + '/peerdb'
            },
            nodeInfo: {
                url: apiVersion + '/nodeinfo'
            }
        });
    })
    .factory('Peerinfo', function ($resource) {
        return $resource(apiVersion + '/peerinfo', {}, { get: { isArray: true } });
    })
    .factory('Stake', function ($resource) {

        return $resource(apiVersion + '/staker/start/:mnemonic/', { mnemonic: '@mnemonic' }, { start: { method: 'post' } });
    })
    .factory('Account', function ($resource) {

        return $resource('', {},
            {
                send: {
                    method: 'post',
                    params: {
                        mnemonic: '@mnemonic',
                        fee: '@fee',
                        amount: '@amount',
                        to: '@to',
                        message: '@message',
                        encrypted: '@encrypted'
                    },
                    url: apiVersion + '/transfer/:mnemonic/:fee/:amount/:to/:message/:encrypted/'
                },
                sign: {
                    method: 'post',
                    url: apiVersion + '/signmessage/:mnemonic/:message/',
                    params: {
                        mnemonic: '@mnemonic',
                        message: '@message'
                    }
                },
                verify: {
                    method: 'get',
                    url: apiVersion + '/verifymessage/:account/:signature/:message/',
                    params: {
                        account: '@account',
                        signature: '@signature',
                        message: '@message'
                    }
                },
                info: {
                    method: 'post',
                    url: apiVersion +  '/mnemonic/info/:mnemonic',
                    params: {
                        mnemonic: '@mnemonic'
                    }
                }
            });
    });



