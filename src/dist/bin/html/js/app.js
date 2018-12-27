
Blacknet.controller('appController', function ($scope, Ledger, Account, Stake) {

    let height = 0, blockStacks = [];
    $scope.blocks = [];
    $scope.nodeInfo = Ledger.nodeInfo();
    $scope.peerInfo = Ledger.peerInfo();

    Ledger.get(function (res) {
        initWS();
        $scope.ledger = res;
        height = res.height;
    });

    $scope.startStaking = function () {

        Stake.start({ mnemonic: $scope.staking_mnemonic }, function (res) {
            $scope.start_staking_result = res.text;
        }, function () {
            $scope.start_staking_result = 'Mnemonic is invalid';
        });
    };

    $scope.queryBalance = function () {

        Ledger.getBalance({ account: $scope.account }, function (data) {
            $scope.balance_result = (data.balance / 1e8).toFixed(2) + ' BLN';
        }, function () {
            $scope.balance_result = '0 BLN';
        });;
    };

    $scope.sendMoney = function () {

        let params = {
            mnemonic: $scope.send_mnemonic,
            fee: $scope.send_fee,
            amount: $scope.send_amount,
            to: $scope.send_to,
            message: $scope.send_message,
            encrypted: $scope.send_encrypted ? '1' : 0
        };
        Account.send(params, function (res) {
            $scope.send_result = res.text;
        }, function () {
            $scope.send_result = 'Bad Request';
        });;
    };

    $scope.signMessage = function () {

        let params = {
            mnemonic: $scope.sign_mnemonic,
            message: $scope.sign_message
        };
        Account.sign(params, function (res) {
            $scope.sign_result = res.text;
        }, function () {
            $scope.sign_result = 'Bad Request';
        });;
    };

    $scope.verifyMessage = function () {

        let params = {
            account: $scope.verify_account,
            signature: $scope.verify_signature,
            message: $scope.verify_message
        };

        Account.verify(params, function (res) {
            $scope.verify_result = res.text;
        }, function () {
            $scope.verify_result = 'invalid signature';
        })
    };

    $scope.mnemonicInfo = function () {

        Account.info({ mnemonic: $scope.mnemonic_info }, function (res) {
            delete res.mnemonic;
            $scope.mnemonic_result = res;
        })
    };

    $scope.showInfo = function (type) {
        $scope.info = Ledger[type]();;
    };

    function updateStatus(message) {

        let hash = message && message.data, block;

        if (!hash) return;

        blockStacks.push(hash);
        processBlock();
    }

    function unix_to_local_time(unix_timestamp) {
        const date = new Date(+(unix_timestamp + '000'));
        const hours = date.getHours();
        const minutes = "0" + date.getMinutes();
        const seconds = "0" + date.getSeconds();
        return hours + ':' + minutes.substr(-2) + ':' + seconds.substr(-2);
    }

    function initWS() {
        let ws = new WebSocket("ws://" + location.host + "/api/v1/notify/block");
        ws.onmessage = updateStatus;
    }

    let running = false;

    function processBlock() {

        let hash = blockStacks.shift();

        if (!hash) {
            running = false;
            return;
        }
        if (running) return;

        Ledger.queryBlock({ hash: hash }, function (data) {

            height++;
            data.height = height;
            data.contentHash = hash;
            data.timeString = unix_to_local_time(data.time);
            if ($scope.blocks.length > 100) {
                $scope.blocks.pop();
            }
            
            $scope.ledger.height = height;
            $scope.blocks = [data].concat($scope.blocks);
            processBlock();
        });
    }

});