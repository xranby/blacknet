/*
 * Copyright (c) 2018-2019 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

void function () {

    const Blacknet = {};
    const blockListEl = $('#block-list'), apiVersion = "/api/v1", body = $("body");;
    const progressStats = $('.progress-stats, .progress-stats-text');
    const dialogPassword = $('.dialog.password'), mask = $('.mask');
    const account = localStorage.account;
    const dialogAccount = $('.dialog.account');


    Blacknet.init = async function () {

        await Blacknet.wait(1000);

        if (account) {

            mask.removeClass('init').hide();
            dialogAccount.hide();
            Blacknet.showProgress();

            $('.overview').find('.overview_account').text(account);

            if (localStorage.isStaking) {
                $('.isStaking').text(localStorage.isStaking);
            }

            mask.on('click', function () {
                mask.hide();
                dialogPassword.hide();
            });
        } else {
            dialogAccount.find('.spinner').hide();
            dialogAccount.find('.account-input').show();
            dialogAccount.find('.enter').unbind().on('click', function () {

                let account = dialogAccount.find('.account_text').val();

                if (/^blacknet[a-z0-9]{59}$/.test(account)) {
                    localStorage.account = account;
                    location.reload();
                } else {
                    alert('Invalid Account');
                }
            });
        }
    };

    Blacknet.balance = async function () {

        let balance = $('.overview_balance');

        $.getJSON(apiVersion + '/ledger/get/' + account + '/', function (data) {
            balance.html(new BigNumber(data.balance).dividedBy(1e8) + ' BLN');
        }).fail(function () {
            balance.html('0.00000000 BLN');
        });
    };



    Blacknet.renderStatus = function () {

        let network = $('.network');
        let ledger = Blacknet.ledger, nodeinfo = Blacknet.nodeinfo;

        network.find('.height').html(ledger.height);
        network.find('.supply').html(new BigNumber(ledger.supply).dividedBy(1e8).toFixed(0));
        network.find('.accounts').html(ledger.accounts);
        network.find('.connections').text(nodeinfo.outgoing + nodeinfo.incoming);
        $('.overview_agent').text(nodeinfo.agent);
    };

    Blacknet.renderOverview = function () {

        let ledger = Blacknet.ledger;

        for (let key in ledger) {

            let value = ledger[key];
            if (key == 'blockTime') {
                value = Blacknet.unix_to_local_time(value);
                Blacknet.renderProgressBar(ledger[key]);
            } else if (key == 'supply') {
                value = new BigNumber(value).dividedBy(1e8) + ' BLN';
            }
            $('.overview_' + key).text(value);
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

            const GENESIS_TIME = 1545555600;
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
    Blacknet.post = function (url, callback, type) {
        return $.post(apiVersion + url, {}, callback, type);
    };

    Blacknet.postPromise = function (url) {
        return $.post(apiVersion + url, {});
    };

    Blacknet.sendMoney = function (mnemonic, amount, to, message, encrypted, callback) {

        let fee = 100000, amountText, url;

        amountText = new BigNumber(amount).toFixed(8);
        amount = new BigNumber(amount).times(1e8);

        url = "/transfer/" + mnemonic + "/" + fee + "/" + amount + "/" + to + "/" + message + "/" + encrypted + "/";

        if (confirm('Are you sure you want to send?\n\n' + amountText + ' BLN to \n' +
            to + '\n\n0.001 BLN added as transaction fee?')) {

            Blacknet.post(url, callback);
        }
    };

    Blacknet.lease = function (mnemonic, type, amount, to, height, callback) {

        let fee = 100000, amountText, url, type_text = type == 'lease' ? 'lease' : 'cancel lease';

        amountText = new BigNumber(amount).toFixed(8);
        amount = new BigNumber(amount).times(1e8);

        if (type == 'lease') {
            url = "/" + type + "/" + mnemonic + "/" + fee + "/" + amount + "/" + to + "/";
        } else {
            url = "/cancellease/" + mnemonic + "/" + fee + "/" + amount + "/" + to + "/" + height + "/";
        }

        if (confirm('Are you sure you want to ' + type_text + '?\n\n' + amountText +
            ' BLN to \n' + to + '\n\n0.001 BLN added as transaction fee?')) {

            Blacknet.post(url, callback);
        }
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

        let url = `/blockdb/get/${hash}`;
        let block = await Blacknet.getPromise(url, 'json');

        block.txns = block.transactions.length;
        Blacknet.renderBlock(block, height, false);

        return block.previous
    }

    Blacknet.renderBlock = async function (block, height, prepend = true) {

        let tmpl = `<tr><td class="narrow height">${height}</td>
                    <td class="size narrow">${block.size}</td>
                    <td class="time narrow">${Blacknet.unix_to_local_time(block.time)}</td>
                    <td class="txns narrow">${block.txns}</td>
                    <td class="generator">${block.generator}</td></tr>`;

        if (prepend)
            $(tmpl).prependTo(blockListEl);
        else
            $(tmpl).appendTo(blockListEl);

        let rowsCount = blockListEl[0].childNodes.length;

        if (rowsCount > 36) {
            blockListEl.find('tr:last-child').remove();
        }
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

    Blacknet.initRecentTransactions = async function () {

        let data = await Blacknet.getPromise('/walletdb/getwallet/' + account, 'json');
        let transactions = data.transactions;

        let array = [], tx = {}, hash;

        while (transactions.length) {

            let tmp = transactions.shift();

            if (typeof tmp == 'string') {

                tx = await Blacknet.getPromise('/walletdb/gettransaction/' + tmp + '/false', 'json');
                hash = tmp;
            } else {

                tx.height = tmp.height;
                tx.time = tmp.time;
                array.push(tx);

                tx = {};
            }
        }

        $('#tx-list').html('');
        array.sort(function (x, y) {
            return y.time - x.time;
        }).map(Blacknet.renderTransaction);

        Blacknet.renderLeaseOption(array);
    };

    Blacknet.renderLeaseOption = function (txns) {

        let leaseTxns, accounts = [], aobj = {}, hobj = {}, height = [];

        leaseTxns = txns.filter(function (tx) {
            return tx.type == 2;
        });

        if (leaseTxns.length == 0) return;

        leaseTxns.map(function (tx) {
            aobj[tx.data.to] = '';
            hobj[tx.height] = '';
        });

        accounts = Object.keys(aobj);
        height = Object.keys(hobj);

        accounts.forEach(function (account) {

            $('#cancel_lease_to').append($("<option></option>").attr("value", account).text(account));
        });

        height.forEach(function (account) {

            $('#cancel_lease_height').append($("<option></option>").attr("value", account).text(account));
        });

        $('.cancel_lease_tab').show();
    };

    Blacknet.renderTransaction = function (tx) {

        let amount = tx.data.amount, tmpl, type, txType, txaccount = tx.from;

        txType = ["Transfer", "Burn", "Lease", "CancelLease", "Bundle", "CreateHTLC",
            "UnlockHTLC", "RefundHTLC", "SpendHTLC", "CreateMultisig", "SpendMultisig"];

        type = txType[tx.type];

        if (tx.type == 254) {
            amount = tx.fee;
            type = 'Generated';
        }

        if (tx.type == 0) {
            if (tx.from == account) {
                type = "Sent to";
                txaccount = tx.data.to;
            } else {
                type = "Received from";
            }
        }

        amount = new BigNumber(amount).dividedBy(1e8).toFixed(8);

        tmpl = `<tr>
                    <td class="narrow" data-i18n="Time">${Blacknet.unix_to_local_time(tx.time)}</td>
                    <td class="narrow" data-i18n="Type">${type}</td>
                    <td class="left" data-i18n="Account">${txaccount}</td>
                    <td class="right" data-i18n="Amount">${amount} <span class="strong">BLN</span></td>
                </tr>`;
        $(tmpl).appendTo('#tx-list')
    };


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

    async function getPeerInfo() {

        let peers = await Blacknet.getPromise('/peerinfo', 'json');
        $('#peer-list').html('');
        peers.map(renderPeer);
    }

    function renderPeer(peer, index) {

        let tmpl = `<tr>
                        <td>${index + 1}</td>
                        <td class="right">${peer.remoteAddress}</td>
                        <td>${peer.agent}</td>
                        <td class="right">${peer.ping}ms</td>
                        <td class="narrow">${peer.timeOffset}</td>
                        <td class="narrow">${peer.totalBytesRead}</td>
                        <td class="narrow">${peer.totalBytesWritten}</td>
                    </tr>`;

        $(tmpl).appendTo("#peer-list");
    }

    Blacknet.ready = async function (callback) {

        let lang = navigator.language || navigator.userLanguage;
        if (lang.indexOf('zh') !== -1) {
            i18n({ locale: 'zh' });
        } else if (lang.indexOf('ja') !== -1) {
            i18n({ locale: 'ja' });
        } else if (lang.indexOf('sk') !== -1) {
            i18n({ locale: 'sk' });
        }

        Blacknet.init();
        await Blacknet.balance();
        await Blacknet.network();
        await Blacknet.initRecentBlocks();

        if (account) {
            await Blacknet.initRecentTransactions();
        }

        Blacknet.startHeight = Blacknet.height + 1;
        callback();
    };

    const timePeerInfo = Blacknet.throttle(getPeerInfo, 1000);
    Blacknet.network = async function () {

        Blacknet.ledger = await Blacknet.getPromise('/ledger', 'json');
        Blacknet.nodeinfo = await Blacknet.getPromise('/nodeinfo', 'json');

        Blacknet.renderStatus();
        Blacknet.renderOverview();

        timePeerInfo();
    };

    window.addEventListener('beforeunload', function (e) {

        if (window.isGenerated) {

            e.preventDefault();
            e.returnValue = '';
        }
    });

    window.Blacknet = Blacknet;
}();