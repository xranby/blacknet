/*
 * Copyright (c) 2018-2020 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

void function () {

    const Blacknet = {};
    const DEFAULT_CONFIRMATIONS = 10;
    const GENESIS_TIME = 1545555600;
    const blockListEl = $('#block-list'), apiVersion = "/api/v2", body = $("body");;
    const progressStats = $('.progress-stats, .progress-stats-text');
    const dialogPassword = $('.dialog.password'), dialogConfirm = $('.dialog.confirm'), mask = $('.mask');
    const account = localStorage.account;
    const dialogAccount = $('.dialog.account');
    const notificationNode = $('.notification.tx').first();
    const txList = $('#tx-list');

    Blacknet.explorer = {
        block: 'https://blnscan.io/',
        blockHeight: 'https://blnscan.io/',
        tx: 'https://blnscan.io/',
        account: 'https://blnscan.io/'
    };

    if (localStorage.explorer) {
        Blacknet.explorer = JSON.parse(localStorage.explorer);
    }

    Blacknet.init = async function () {

        await Blacknet.wait(1000);

        if (account) {

            mask.removeClass('init').hide();
            dialogAccount.hide();
            Blacknet.showProgress();

            $('.overview').find('.overview_account').text(account);

            if (localStorage.isStaking) {
                $('.is_staking').text(localStorage.isStaking);
            }

            mask.on('click', function () {
                mask.hide();
                dialogPassword.hide();
                dialogConfirm.hide();
            });
        } else {
            dialogAccount.find('.spinner').hide();
            dialogAccount.find('.account-input').show();
            dialogAccount.find('.enter').unbind().on('click', async function () {

                let account = dialogAccount.find('.account_text').val();
                account = account.trim();

                if (Blacknet.verifyAccount(account)) {
                    localStorage.account = account;
                } else if (Blacknet.verifyMnemonic(account)) {
                    account = await Blacknet.mnemonicToAddress(account);
                    localStorage.account = account;
                } else {
                    Blacknet.message("Invalid account/mnemonic", "warning")
                    dialogAccount.find('.account_text').focus()
                    return
                }
                location.reload();
            });
        }
    };

    Blacknet.mnemonicToAddress = async function (mnemonic) {
        let postdata = {
            mnemonic: mnemonic
        };
        let mnemonicInfo = await Blacknet.postPromise("/mnemonic", postdata, true);
        return mnemonicInfo.address;
    };

    /**
     * account balance
     * @method balance
     * @for Blacknet
     * @param {null} 
     * @return {null}
     */
    Blacknet.balance = async function () {

        let balance = $('.overview_balance'),
            confirmedBalance = $('.overview_confirmed_balance'),
            stakingBalance = $('.overview_staking_balance');;

        $.getJSON(apiVersion + '/account/' + account + '/', function (data) {
            balance.html(Blacknet.toBLNString(data.balance));
            confirmedBalance.html(Blacknet.toBLNString(data.confirmedBalance));
            stakingBalance.html(Blacknet.toBLNString(data.stakingBalance));

        }).fail(function () {
            balance.html('0.00000000 BLN');
        });
    };

    Blacknet.toBLNString = function (number) {
        return new BigNumber(number).dividedBy(1e8).toFixed(8) + ' BLN';
    };



    Blacknet.renderStatus = function () {

        let network = $('.network');
        let warnings = $('.overview_warnings'), warnings_row = $('.overview_warnings_row');
        let ledger = Blacknet.ledger, nodeinfo = Blacknet.nodeinfo;

        network.find('.height').html(ledger.height);
        network.find('.supply').html(new BigNumber(ledger.supply).dividedBy(1e8).toFixed(0));
        network.find('.connections').text(nodeinfo.outgoing + nodeinfo.incoming);
        $('.overview_version').text(nodeinfo.version);

        if (nodeinfo.warnings.length > 0) {
            warnings.text(nodeinfo.warnings);
            warnings_row.show();
        } else {
            warnings.text("");
            warnings_row.hide();
        }
    };

    Blacknet.renderOverview = async function () {

        let ledger = Blacknet.ledger;

        for (let key in ledger) {

            let value = ledger[key];
            if (key == 'blockTime') {
                value = Blacknet.unix_to_local_time(value);
                Blacknet.renderProgressBar(ledger[key]);
            } else if (key == 'height') {
                $('.overview_height').prop('href', Blacknet.explorer.blockHeight + value);
            } else if (key == 'blockHash') {
                $('.overview_blockHash').prop('href', Blacknet.explorer.block + value);
            } else if (key == 'supply') {
                value = new BigNumber(value).dividedBy(1e8) + ' BLN';
            }
            $('.overview_' + key).text(value);
        }

        let staking = await Blacknet.getPromise('/staking/' + account);

        for (let key in staking) {

            $('.staking_info').find('.' + key).text(staking[key]);
        }

    };

    Blacknet.renderProgressBar = async function (timestamp) {

        let secs = Date.now() / 1000 - timestamp, totalSecs, pecent, timeBehindText = "", now = Date.now();
        let HOUR_IN_SECONDS = 60 * 60;
        let DAY_IN_SECONDS = 24 * 60 * 60;
        let WEEK_IN_SECONDS = 7 * 24 * 60 * 60;
        let YEAR_IN_SECONDS = 31556952; // Average length of year in Gregorian calendar

        if (secs < 5 * 60) {
            timeBehindText = undefined;
        } else if (secs < 2 * DAY_IN_SECONDS) {
            timeBehindText = (secs / HOUR_IN_SECONDS).toFixed(2) + " hour(s)";
        } else if (secs < 2 * WEEK_IN_SECONDS) {
            timeBehindText = (secs / DAY_IN_SECONDS).toFixed(2) + " day(s)";
        } else if (secs < YEAR_IN_SECONDS) {
            timeBehindText = (secs / WEEK_IN_SECONDS).toFixed(2) + " week(s)";
        } else {
            let years = secs / YEAR_IN_SECONDS;
            let remainder = secs % YEAR_IN_SECONDS;
            timeBehindText = years.toFixed(2) + " year(s) and " + remainder.toFixed(2) + "week(s)";
        }

        if (!Blacknet.startTime) {
            Blacknet.startTime = GENESIS_TIME;
        }
        Blacknet.timeBehindText = timeBehindText;

        if (timeBehindText == undefined) {
            progressStats.hide();
            return;
        }

        totalSecs = Date.now() / 1000 - Blacknet.startTime;
        pecent = (secs * 100) / totalSecs;

        pecent = 100 - pecent;

        $('.progress-bar').css('width', `${pecent}%`);
        $('.progress-stats-text').text(timeBehindText + " behind");
    }

    Blacknet.showProgress = function () {

        if (Blacknet.timeBehindText != undefined) {
            progressStats.show();
        }
    };

    Blacknet.get = function (url, callback) {

        return $.get(apiVersion + url, callback);
    };

    Blacknet.getPromise = function (url, type) {

        return type == 'json' ? $.getJSON(apiVersion + url) : $.get(apiVersion + url);
    };

    Blacknet.post = function (url, data, callback, fail) {

        let options = {
            url: apiVersion + url,
            data: data,
            type: 'POST',
            success: callback,
            fail: fail
        };

        return $.ajax(options);
    };

    Blacknet.postPromise = function (url, data, isNeedAlert) {

        return $.post(apiVersion + url, data).fail(function (res) {
            if (isNeedAlert && res.responseText) alert(res.responseText);
        });
    };

    Blacknet.sendMoney = function (mnemonic, amount, to, message, encrypted, callback) {

        let fee = 100000, amountText;

        amountText = new BigNumber(amount).toFixed(8);
        amount = new BigNumber(amount).times(1e8).toNumber();

        Blacknet.confirm('Are you sure you want to send?\n\n' + amountText + ' BLN to \n' +
            to + '\n\n0.001 BLN added as transaction fee?', function (flag) {
                if (flag) {

                    let postdata = {
                        mnemonic: mnemonic,
                        amount: amount,
                        fee: fee,
                        to: to,
                        message: message,
                        encrypted: encrypted
                    };
                    Blacknet.post('/transfer', postdata, callback);
                }
            })
    };

    Blacknet.lease = function (mnemonic, type, amount, to, height, callback) {

        let fee = 100000, amountText, type_text = type == 'lease' ? 'lease' : 'cancel lease';

        amountText = new BigNumber(amount).toFixed(8);
        amount = new BigNumber(amount).times(1e8).toNumber();

        Blacknet.confirm('Are you sure you want to ' + type_text + '?\n\n' + amountText +
            ' BLN to \n' + to + '\n\n0.001 BLN added as transaction fee?', function (flag) {
                if (flag) {

                    let postdata = {
                        mnemonic: mnemonic,
                        amount: amount,
                        fee: fee,
                        to: to
                    };

                    if (height) {
                        postdata.height = height;
                    }

                    Blacknet.post('/' + type, postdata, callback);
                }
            })
    };

    Blacknet.wait = function (timeout) {
        return new Promise(function (resolve, reject) {
            setTimeout(function () {
                resolve();
            }, timeout);
        });
    };

    Blacknet.unix_to_local_time = function (unix_timestamp) {

        let date = new Date(unix_timestamp * 1000);
        let hours = "0" + date.getHours();
        let minutes = "0" + date.getMinutes();
        let seconds = "0" + date.getSeconds();
        let day = date.getDate();
        let year = date.getFullYear();
        let month = date.getMonth() + 1;

        return year + "-" + ('0' + month).substr(-2) + "-" +
            ('0' + day).substr(-2) + " " + hours.substr(-2) + ':' + minutes.substr(-2) + ':' + seconds.substr(-2);
    }

    Blacknet.addBlock = async function (hash, height) {

        let url = `/block/${hash}`;
        let block = await Blacknet.getPromise(url, 'json');

        Blacknet.template.block(blockListEl, block, height, false);

        return block.previous
    }

    Blacknet.initRecentBlocks = async function () {

        let i = 0;
        let hash = Blacknet.ledger.blockHash;
        let height = Blacknet.ledger.height;

        if (height < 36) return;

        while (i++ < 35) {
            hash = await Blacknet.addBlock(hash, height);
            height--;
        }
    }

    Blacknet.serializeTx = function (transactions) {
        let txs = [];

        for (hash in transactions) {
            let tx = transactions[hash];
            tx.hash = hash;
            txs.push(tx);
        }

        txs.sort(function (x, y) {
            return y.time - x.time;
        });

        return txs;
    }

    Blacknet.initRecentTransactions = async function () {
        Blacknet.txtype = "all";

        let array = await Blacknet.getTxDataList(0);
        Blacknet.renderTxs(array);
        Blacknet.txpage = 0;
        await Blacknet.renderLease();
    };

    Blacknet.getTxDataList = async function (page) {

        let max = 100;
        let offset = page * max;
        let url = `/wallet/${account}/listtransactions/${offset}/${max}`;

        if (Blacknet.txtype != 'all') {
            url += '/' + Blacknet.txtype;
        }

        let transactions = await Blacknet.getPromise(url, 'json');
        let array = [];
        array = transactions.map(function (tx) {
            let obj = tx.transaction;
            obj.confirmations = tx.confirmations;
            obj.time = tx.receiveTime;
            return obj;
        });
        return array;
    };

    Blacknet.moreTransactions = async function () {
        Blacknet.txpage++;
        let array = await Blacknet.getTxDataList(Blacknet.txpage, Blacknet.txtype);
        Blacknet.renderTxs(array);
    }

    Blacknet.switchTxRender = async function (type) {

        Blacknet.txpage = 0;
        Blacknet.txtype = type;

        $('tr.preview').remove();
        $('#tx-progress').show();
        $('.tx-foot .no_tx_yet').hide();
        let more = $('.tx-foot .show_more_txs');
        more.hide();

        let array = await Blacknet.getTxDataList(Blacknet.txpage);

        Blacknet.renderTxs(array);
        Blacknet.txpage = 0;
        

        if (array.length < 100) more.hide();
        else more.show();

    };

    Blacknet.renderTxs = async function (txArray) {

        let txamount = txArray.length, txProgress = $('#tx-progress'),
            showMore = $('.tx-foot .show_more_txs'),
            noTxYet = $('.tx-foot .no_tx_yet');

        txArray.length == 0 ? noTxYet.show() : noTxYet.hide();
        txProgress.hide();

        for (let tx of txArray) {
            await Blacknet.renderTransaction(tx);
        }

        txamount == 100 ? showMore.show() : showMore.hide();
    };

    Blacknet.stopMoreTxs = function () {
        Blacknet.stopMore = true;
    }

    Blacknet.renderTransaction = async function (tx, prepend) {

        let node = txList.find('.txhash' + tx.height + tx.time);
        if (typeof tx.height == 'undefined') {
            tx.height = 0;
        }
        // if tx already render, update status
        if (node.html()) {
            node.find('.status').html(tx.confirmations > 10 ? 'Confirmed' : `${tx.confirmations} confirmations`)
            // await Blacknet.renderTxStatus(0, node[0]);
            return;
        }

        node = await Blacknet.template.transaction(tx, account);
        node.appendTo(txList);
        // prepend ? node.prependTo(txList) : node.appendTo(txList);

    };

    Blacknet.renderLease = async function () {

        let outLeases = await Blacknet.getPromise('/wallet/' + account + '/outleases');
        $('.cancel_lease_tab').show();

        if (outLeases.length > 0) {

            $('#leases-list').html('');
            outLeases.map(Blacknet.template.lease);
        }
    };

    Blacknet.getStatusText = async function (height, hash) {

        let confirmations = Blacknet.ledger.height - height + 1, statusText = 'Confirmed';
        if (height == 0) {

            confirmations = await Blacknet.getPromise('/wallet/' + account + '/confirmations/' + hash);
            statusText = `${confirmations} Confirmations`;
        } else if (confirmations < DEFAULT_CONFIRMATIONS) {

            statusText = `${confirmations} Confirmations`;
        }
        return statusText;
    };

    Blacknet.getTxTypeName = function (type) {
        let typeNames = [
            "Transfer",
            "Burn",
            "Lease",
            "CancelLease",
            "BApp",
            "CreateHTLC",
            "UnlockHTLC",
            "RefundHTLC",
            "SpendHTLC",
            "CreateMultisig",
            "SpendMultisig",
            "WithdrawFromLease",
            "ClaimHTLC"
        ];

        let name = typeNames[type];

        if (type == 16) {
            name = "Batch";
        } else if (type == 254) {
            name = "Generated";
        } else if (type == 0) {
            if (tx.from == account) {
                name = "Sent to";
            } else {
                name = "Received from";
            }
        }
        return name;
    };

    Blacknet.getFormatBalance = function (balance) {

        return new BigNumber(balance).dividedBy(1e8).toFixed(8) + ' BLN';
    };

    Blacknet.newTransactionNotify = function (tx) {

        let notification = notificationNode.clone();
        let time = Blacknet.unix_to_local_time(tx.time);

        //TODO MultiData
        let dataType = tx.data[0].type;
        let txData = tx.data[0].data;

        let type = Blacknet.getTxTypeName(dataType), amount = Blacknet.getFormatBalance(txData.amount);;

        if (type == 'Generated') {
            amount = Blacknet.getFormatBalance(tx.fee);
        }

        notification.find('.time').text(time);
        notification.find('.type').text(type);
        notification.find('.amount').text(amount);

        // notification.appendTo('body').show();

        // notification.delay(2000).animate({ top: "-100px", opacity: 0 }, 1000, function () {
        //     notification.remove();
        // });
    };



    Blacknet.renderBlock = async function (block, height, prepend = true) {

        Blacknet.template.block(blockListEl, block, height, prepend);
    }

    Blacknet.throttle = function (fn, threshhold = 250) {

        let last, timer;

        return function () {

            let context = this;
            let args = arguments;
            let now = +new Date();

            if (last && now < last + threshhold) {
                clearTimeout(timer);

                timer = setTimeout(function () {
                    last = now;
                    fn.apply(context, args);
                }, threshhold);

            } else {
                last = now;
                fn.apply(context, args);
            }
        }
    }

    Blacknet.getPeerInfo = async function () {

        let peers = await Blacknet.getPromise('/peers', 'json');
        $('#peer-list').html('');
        peers.map(Blacknet.template.peer);
    }


    Blacknet.ready = async function (callback) {

        let lang = navigator.language || navigator.userLanguage;
        if (lang.indexOf('zh') !== -1) {
            i18n({ locale: 'zh_CN' });
        } else if (lang.indexOf('ja') !== -1) {
            i18n({ locale: 'ja' });
        } else if (lang.indexOf('sk') !== -1) {
            i18n({ locale: 'sk' });
        } else if (lang.indexOf('de') !== -1) {
            i18n({ locale: 'de' });
        }
        Blacknet.initExplorer();

        Blacknet.init();
        await Blacknet.balance();
        await Blacknet.network();
        await Blacknet.initRecentBlocks();

        if (account) {
            await Blacknet.initRecentTransactions();
        }

        callback();
    };

    Blacknet.refreshBalance = async function () {

        await Blacknet.balance();
    };

    Blacknet.initExplorer = function () {

        let obj = Blacknet.explorer;
        for (let key in obj) {

            $('.config').find('#' + key).val(obj[key]);
        }

    };

    const timePeerInfo = Blacknet.throttle(Blacknet.getPeerInfo, 1000);
    Blacknet.network = async function () {

        Blacknet.ledger = await Blacknet.getPromise('/ledger', 'json');
        Blacknet.nodeinfo = await Blacknet.getPromise('/node', 'json');

        Blacknet.renderStatus();
        Blacknet.renderOverview();

        timePeerInfo();
    };

    /**
     * verify mnemonic
     * @method verifyMnemonic
     * @for Blacknet
     * @param {string} mnemonic
     * @return {boolean} true/false
     */
    Blacknet.verifyMnemonic = function (mnemonic) {
        if (Object.prototype.toString.call(mnemonic) === "[object String]"
            && mnemonic.split(" ").length == 12) {
            return true
        }
        return false
    }
    /**
     * verify account address
     * @method verifyAccount
     * @for Blacknet
     * @param {string} account
     * @return {boolean} true/false
     */
    Blacknet.verifyAccount = function (account) {
        // TODO Bech32验证、回归测试模式
        if (Object.prototype.toString.call(account) === "[object String]" &&
            account.length > 21 && (/^blacknet[a-z0-9]{59}$/.test(account) || /^rblacknet[a-z0-9]{59}$/.test(account))) {
            return true
        }
        return false
    }
    /**
     * verify amount
     * @method verifyAmount
     * @for Blacknet
     * @param {string} amount
     * @return {boolean} true/false
     */
    Blacknet.verifyAmount = function (amount) {
        if (/\d+/.test(amount) && amount > 0) {
            return true
        }
        return false
    }
    /**
     * verify message
     * @method verifyMessage
     * @for Blacknet
     * @param {string} message
     * @return {boolean} true/false
     */
    Blacknet.verifyMessage = function (message) {
        if (Object.prototype.toString.call(message) === "[object String]" && message.length > 0) {
            return true
        }
        return false
    }
    /**
     * verify sign
     * @method verifySign
     * @for Blacknet
     * @param {string} sign
     * @return {boolean} true/false
     */
    Blacknet.verifySign = function (sign) {
        if (Object.prototype.toString.call(sign) === "[object String]" && sign.length === 128) {
            return true
        }
        return false
    }
    /**
     * verify network address
     * @method verifyNetworkAddress
     * @for Blacknet
     * @param {string} network address
     * @return {boolean} true/false
     */
    Blacknet.verifyNetworkAddress = function (address) {
        // ipv4 | ipv6 | tor | i2p
        if (Object.prototype.toString.call(address) === "[object String]" &&
            address.length >= 7 && address.length <= 70) {
            return true
        }
        return false
    }
    /**
     * verify network port
     * @method verifyNetworkPort
     * @for Blacknet
     * @param {string} port
     * @return {boolean} true/false
     */
    Blacknet.verifyNetworkPort = function (port) {
        if (/\d+/.test(port) && port >= 0 && port <= 65535) {
            return true
        }
        return false
    }

    Blacknet.confirm = function (text, fn) {
        mask.show();
        dialogConfirm.find(".body").html(text.replace(/\n/g, "<br/>"))
        dialogConfirm.show().find('.confirm, .cancel').unbind().on('click', function () {
            if (Object.prototype.toString.call(fn) === "[object Function]") {
                fn.call(this, $(this).hasClass("confirm"));
            }
            if (!dialogPassword.is(":visible")) {
                mask.hide();
            }
            dialogConfirm.hide().find('.confirm,.cancel').unbind();
        });
    }

    Blacknet.message = function (msg, type) {
        if (window.i18nData && window.i18nData[msg.toLocaleLowerCase()]) {
            msg = window.i18nData[msg.toLocaleLowerCase()]
        }
        Blacknet.template.message(msg, type)
    }

    window.addEventListener('beforeunload', function (e) {

        if (window.isGenerated) {

            e.preventDefault();
            e.returnValue = '';
        }
    });




    window.Blacknet = Blacknet;
}();
