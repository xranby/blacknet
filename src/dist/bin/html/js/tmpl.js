


Blacknet.template = {


    transaction: async function (tx, account) {

        let amount = tx.data.amount, tmpl, txfee, type, status, txaccount = tx.from;

        type = Blacknet.getTxType(tx);
        txfee = Blacknet.getFormatBalance(tx.fee);

        if (tx.type == 254) {
            amount = tx.fee;
            txfee = '';
        }
        if (tx.type == 0 && tx.from == account) {
            txaccount = tx.data.to;
        }

        if (tx.time * 1000 < Date.now() - 1000 * 10) {
            status = 'Confirmed';
        } else {
            status = await Blacknet.getStatusText(tx.height, tx.hash);
        }

        amount = Blacknet.getFormatBalance(amount);

        tmpl =
            `<tr class="preview txhash${tx.hash}" data-hash="${tx.height}${tx.time}"  data-height="${tx.height}">
                <td class="narrow">${Blacknet.unix_to_local_time(tx.time)}</td>
                <td class="narrow">${type}</td>
                <td class="left">${txaccount}</td>
                <td class="right"><span class="strong">${amount}</span></td>
                <td class="left status" data-height="${tx.height}">${status}</td>
            </tr>
            <tr class="undis tx-item" data-time="${tx.time}" data-hash="${tx.hash}"  data-height="${tx.height}">
                <td colspan="5">
                    <dl>
                        <dt>Time</dt>
                        <dd>${Blacknet.unix_to_local_time(tx.time)}</dd>
                    </dl>
                    <dl>
                        <dt>Status</dt>
                        <dd class="status">${status}</dd>
                    </dl>
                    <dl>
                        <dt>From</dt>
                        <dd class="${tx.from == account ? 'current' : ''}">${tx.from}</dd>
                    </dl>
                    <dl class="to">
                        <dt>To</dt>
                        <dd class="${tx.data.to == account ? 'current' : ''}">${tx.data.to || ''}</dd>
                    </dl>
                    <dl>
                        <dt>Type</dt>
                        <dd>${type.replace(' from', '')}</dd>
                    </dl>
                    <dl class="fee">
                        <dt>Fee</dt>
                        <dd><span class="strong">${txfee}</span></dd>
                    </dl>
                    <dl>
                        <dt>Amount</dt>
                        <dd><span class="strong">${amount}</span></dd>
                    </dl>
                    <dl>
                        <dt>Size</dt>
                        <dd>${tx.size}(bytes)</dd>
                    </dl>
                    <dl>
                        <dt>Hash</dt>
                        <dd>${tx.hash}</dd>
                    </dl>
                    <dl class="sign_text">
                        <dt>Signature</dt>
                        <dd>${tx.signature}</dd>
                    </dl>
                    <dl class="msg_text">
                        <dt>Message</dt>
                        <dd class="message"></dd>
                    </dl>
                    <dl>
                        <dt>Block Height</dt>
                        <dd>${tx.height}</dd>
                    </dl>
                </td>
            </tr>`;


        let node = $(tmpl), msgNode = node.find('.message'), message;
        if (tx.type == 0) {
            if (tx.data.message.type == 0) {
                message = tx.data.message.message;
            } else if (tx.data.message.type == 1) {
                message = "Encrypted message";
            } else {
                message = "Non-standard message";
            }
            msgNode.text(message);
        }

        if (!message) node.find('.msg_text').hide();
        if (tx.type == 254) {
            node.find('.sign_text,.to,.fee').hide();
        }
        return node;
    },

    peer: function (peer, index) {

        let tmpl =
            `<tr>
                <td>${index + 1}</td>
                <td class="right">${peer.remoteAddress}</td>
                <td>${peer.agent}</td>
                <td class="right">${peer.ping}ms</td>
                <td class="narrow">${peer.timeOffset}</td>
                <td class="narrow">${peer.totalBytesRead}</td>
                <td class="narrow">${peer.totalBytesWritten}</td>
            </tr>`;

        $(tmpl).appendTo("#peer-list");
    },

    block: async function (blockListEl, block, height, prepend = true) {

        let op = prepend ? 'prependTo' : 'appendTo';

        let tmpl = `<tr><td class="narrow height">${height}</td>
                    <td class="size narrow">${block.size}</td>
                    <td class="time narrow">${Blacknet.unix_to_local_time(block.time)}</td>
                    <td class="txns narrow">${block.txns}</td>
                    <td class="generator">${block.generator}</td></tr>`;


        $(tmpl)[op](blockListEl);

        let rowsCount = blockListEl[0].childNodes.length;

        if (rowsCount > 36) {
            blockListEl.find('tr:last-child').remove();
        }
    }



};