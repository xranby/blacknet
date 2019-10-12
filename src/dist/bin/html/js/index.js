/*
 * Copyright (c) 2018-2019 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

$(document).ready(function () {

    const menu = $('.main-menu'), panel = $('.rightpanel'), apiVersion = "/api/v2", body = $("body");
    const hash = localStorage.hashIndex || 'overview';
    const dialogPassword = $('.dialog.password'),mask = $('.mask');
    let blockStack = [];
    let Mini_Lease = 1000;

    menu.find('a[data-index="' + hash + '"]').parent().addClass('active');
    
    
    function getMnemoic(){
        
        return $.trim(dialogPassword.find('.mnemonic').val());
    }
    function staking_click(type) {

        return function () {
            mask.show();
            dialogPassword.show().find('.confirm').unbind().on('click', function () {

                let mnemonic = getMnemoic();

                //验证助记词
                if(!Blacknet.verifyMnemonic(mnemonic)){
                    Blacknet.message("Invalid mnemonic", "warning")
                    dialogPassword.find('.mnemonic').focus()
                    return
                }   
                type == 'isstaking' ? refreshStaking(mnemonic, type) : changeStaking(mnemonic, type);
            });
        }
    }

    async function postStaking(mnemonic, type, callback){

        let url = '/' + type;
        let postdata = {
            mnemonic: mnemonic
        };
        Blacknet.post(url, postdata, callback, function () {
            clearPassWordDialog();
            timeAlert('Invalid mnemonic');
        });
    }

    async function refreshStaking(mnemonic, type) {

        let stakingText = $('.is_staking');
        stakingText.text('loading');
        clearPassWordDialog();
        await Blacknet.wait(1000);
        postStaking(mnemonic, type, function(ret){
            localStorage.isStaking = ret;
            stakingText.text(ret);
        });
    }

    async function changeStaking(mnemonic, type) {

        postStaking(mnemonic, type, function(ret){

            let msg = ret == 'false' ? 'FAILED!' :'SUCCESS!';

            timeAlert(type + ' ' + msg);
            clearPassWordDialog();
            refreshStaking(mnemonic, 'isstaking');
        });
    }

    function menuSwitch() {

        const target = $(this), index = target.find('a').attr('data-index');

        target.addClass('active').siblings().removeClass('active');
        panel.find('.' + index).show().siblings().hide();

        localStorage.hashIndex = index;
        return false;
    }

    function sign() {
        let mnemonic = $('#sign_mnemonic').val();
        mnemonic = $.trim(mnemonic);
        let message = $('#sign_message').val();
        if(!Blacknet.verifyMnemonic(mnemonic)){
            Blacknet.message("Invalid mnemonic", "warning")
            $('#sign_mnemonic').focus()
            return
        }
        if(!Blacknet.verifyMessage(message)){
            Blacknet.message("Invalid message", "warning")
            $('#sign_message').focus()
            return
        }
        let postdata = {
            mnemonic: mnemonic,
            message: message
        };
        Blacknet.post('/signmessage', postdata, function(data){
            $('#sign_result').text(data).parent().removeClass("hidden")
        });
    }
    function verify() {
        let account = $('#verify_account').val();
        let signature = $('#verify_signature').val();
        let message = $('#verify_message').val();
        let url = "/verifymessage/" + account + "/" + signature + "/" + message + "/";
        if(!Blacknet.verifyAccount(account)) {
            Blacknet.message("Invalid account", "warning")
            $('#verify_account').focus()
            return 
        }
        if(!Blacknet.verifySign(signature)){
            Blacknet.message("Invalid signature", "warning")
            $('#verify_signature').focus()
            return
        }
        if(!Blacknet.verifyMessage(message)){
            Blacknet.message("Invalid message", "warning")
            $('#verify_message').focus()
            return
        }
        Blacknet.get(url, function(data){
            $('#verify_result').text(data).parent().removeClass("hidden")
        });
    }
    function mnemonic_info() {
        let mnemonic = $('#mnemonic_info_mnemonic').val();
        mnemonic = $.trim(mnemonic);
        let postdata = {
            mnemonic: mnemonic
        };
        if(!Blacknet.verifyMnemonic(mnemonic)){
            Blacknet.message("Invalid mnemonic", "warning")
            $('#mnemonic_info_mnemonic').focus()
            return
        }
        Blacknet.post('/mnemonic', postdata, function (data) {
            let html = '';
            data.mnemonic = '[hidden]';

            html += 'mnemonic: ' + data.mnemonic;
            html += '\naddress: ' + data.address;
            html += '\npublicKey: ' + data.publicKey;
            $('#mnemonic_info_result').text(html).parent().removeClass("hidden")
        });
    }

    function transfer_click(type) {
        return function () {
            let el = this;

            switch (type) {
                case 'send': transfer(); break;
                case 'lease': lease(); break;
                case 'cancel_lease': cancel_lease(el); break;
            }
        }
    }

    function input_mnemonic(fn){
        mask.show();
        dialogPassword.show().find('.confirm').unbind().on('click', function () {
            let mnemonic = getMnemoic();
            //验证助记词
            if(!Blacknet.verifyMnemonic(mnemonic)){
                Blacknet.message("Invalid mnemonic", "warning")
                dialogPassword.find('.mnemonic').focus()
                return
            }
            if(Object.prototype.toString.call(fn) === "[object Function]"){
                fn.call(this, mnemonic);
            }
        });
    }

    function transfer() {
        let to = $('#transfer_to').val();
        let amount = $('#transfer_amount').val();
        let message = $('#transfer_message').val();
        let encrypted = message && $('#transfer_encrypted').prop('checked') ? "1" : "0";
        if(!Blacknet.verifyAccount(to)) {
            Blacknet.message("Invalid account", "warning")
            $('#transfer_to').focus()
            return 
        }
        if(!Blacknet.verifyAmount(amount)) {
            Blacknet.message("Invalid amount", "warning")
            $('#transfer_amount').focus()
            return 
        }

        input_mnemonic(function (mnemonic) {

            Blacknet.sendMoney(mnemonic, amount, to, message, encrypted, function (data) {
                $('#transfer_result').text(data).parent().removeClass("hidden")
                clearPassWordDialog();
            });
        })
    }

    function lease() {
        let to = $('#lease_to').val();
        let amount = $('#lease_amount').val();
        if(!Blacknet.verifyAccount(to)) {
            Blacknet.message("Invalid account", "warning")
            $('#lease_to').focus()
            return 
        }
        if(!Blacknet.verifyAmount(amount)) {
            Blacknet.message("Invalid amount", "warning")
            $('#lease_amount').focus()
            return 
        }

        if(+amount < Mini_Lease){
            Blacknet.message("Lease amount must > 1000 BLN", "warning")
            $('#lease_amount').focus()
            return
        }

        input_mnemonic(function (mnemonic) {
            Blacknet.lease(mnemonic, 'lease', amount, to, 0, function (data) {
                $('#lease_result').text(data).parent().removeClass("hidden")
                clearPassWordDialog();
            });
        })
    }


    function cancel_lease(el) {
        let data = el.dataset;
        let to = data.account;
        let amount = data.amount;
        let height = data.height;

        input_mnemonic(function (mnemonic) {
            Blacknet.lease(mnemonic, 'cancellease', amount, to, height, function (data) {
                Blacknet.message("Cancel Lease Success", "success");
                $('#cancel_lease_result').text(data).parent().removeClass("hidden")
                clearPassWordDialog();
                Blacknet.renderLease();
            });
        })
    }

    function clearPassWordDialog() {
        mask.hide();
        dialogPassword.hide().find('.confirm').unbind();
        dialogPassword.find('.mnemonic').val('');
    }

    function timeAlert(msg, timeout) {
        setTimeout(function () {
            Blacknet.message(msg, "warning")
        }, timeout || 100);
    }

    function switchAccount() {

        localStorage.account = "";
        location.reload();
    }

    async function newAccount() {
        $('.account.dialog').hide();
        $('.newaccount.dialog').show();
        let wordlist = "english";
        let url = '/generateaccount/' + wordlist;
        let mnemonicInfo = await Blacknet.getPromise(url, 'json');
        $('#new_account_text').val(mnemonicInfo.address);
        $('#new_mnemonic').val(mnemonicInfo.mnemonic);
        window.isGenerated = true;
    }

    function newAccountNext() {

        let status = $('#confirm_mnemonic_warning').prop('checked');

        if (!status) {

            $('#confirm_mnemonic_warning_container label').css('color', 'red');
        } else {
            location.reload();
        }
        return false;
    }


    async function blockStackProcess() {

        let block;

        if (blockStack.length == 0) return;

        if (blockStack.length > 100) {

            blockStack = blockStack.slice(-35);
        }

        block = blockStack.shift();

        await Blacknet.renderBlock(block, block.height);
        await Blacknet.network();

        if (blockStack.length == 0) {
            Blacknet.refreshBalance();
            Blacknet.refreshTxConfirmations();
        }
    }

    setInterval(blockStackProcess, 100);

    function confirm_mnemonic_warning() {
        window.isGenerated = !this.checked;
    }

    async function addPeer() {
        let address = $('#ip_address').val(), port = $('#ip_port').val();

        if(!Blacknet.verifyNetworkAddress(address)) {
            Blacknet.message("Invalid address", "warning")
            $('#ip_address').focus()
            return 
        }
        if(!Blacknet.verifyNetworkPort(port)) {
            Blacknet.message("Invalid port", "warning")
            $('#ip_port').focus()
            return
        }

        let result = await Blacknet.getPromise(`/addpeer/${address}/${port}/true`);
        if(result == 'true') result = "Connected";

        await Blacknet.network();

        Blacknet.message(`${address} ${result}`, "success")

        $('#ip_address').val('');
    }

    Blacknet.ready(function () {

        if (!localStorage.account) return;

        let ws = new WebSocket("ws://" + location.host + "/api/v2/websocket");

        ws.onopen = function(){
            let blocks = {
                command: "subscribe",
                route: "block"
            };
            let wallet = {
                command: "subscribe",
                route: "wallet",
                address: localStorage.account
            };
            ws.send(JSON.stringify(blocks));
            ws.send(JSON.stringify(wallet));
        };

        ws.onmessage = function(message){
            if (message.data) {
                let response = JSON.parse(message.data);

                if (response.route == "block") {
                    blockStack.push(response.message);
                } else if (response.route == "transaction") {
                    Blacknet.renderTransaction(response.message, true);
                    if(tx.time * 1000 > Date.now() - 1000*60){
                        Blacknet.newTransactionNotify(response.message);
                    }
                }
            }
        };
        
    });

    async function disconnect(){

        let ret = await Blacknet.getPromise('/disconnectpeer/' + this.dataset.peerid + '/true');
        if(ret == 'true'){
            await Blacknet.getPeerInfo();
        }
    }


    async function renderTx(){

        let type = this.dataset.type;
        
        Blacknet.stopMoreTxs = true;
        $(this).addClass('active').siblings().removeClass('active');

        if(type == 'all'){
            await Blacknet.renderTxs(Blacknet.txIndex);
        }else{
            await Blacknet.renderTxs(Blacknet.txIndex, type);
        }
        Blacknet.stopMoreTxs = false;

    }

    function explorerSave(){

        let obj = Blacknet.explorer, el = $('.config');

        for(let key in obj){

            let v = el.find('#' + key).val();

            obj[key] = v;

        }

        localStorage.explorer = JSON.stringify(obj);
    }


    menu.on('click', 'li', menuSwitch);
    panel.find('.' + hash).show();

    body.on("click", "#stop_staking", staking_click('stopstaking'))
        .on("click", "#start_staking", staking_click('startstaking'))
        .on("click", "#refresh_staking", staking_click('isstaking'))
        .on("click", "#transfer", transfer_click('send'))
        .on("click", "#lease", transfer_click('lease'))
        .on("click", ".cancel_lease_btn", transfer_click('cancel_lease'))
        .on("click", "#sign", sign)
        .on("click", "#verify", verify)
        .on("click", "#mnemonic_info", mnemonic_info)
        .on("click", "#add_peer_btn", addPeer)
        .on("click", "#switch_account", switchAccount)
        .on("click", "#new_account", newAccount)
        .on("input", "#confirm_mnemonic_warning", confirm_mnemonic_warning)
        .on("click", "#new_account_next_step", newAccountNext)
        .on("click", "#peer-table .disconnect", disconnect)
        .on("click", ".filter a", renderTx)
        .on('click', '#explorer_save', explorerSave)
        .on("click", ".tx-foot .show_more_txs", function(){
            $(this).hide();
            Blacknet.stopMore = false;
            Blacknet.showMoreTxs();
            return false;
        });


});