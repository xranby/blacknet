/*
 * Copyright (c) 2019-2020 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */



async function i18n(config) {

    let data = await $.getJSON('i18n/' + config.locale + '.json');
    
    for(let key in data){

        data[key.toLowerCase()] = data[key];
    }

    window.i18nData = data
    
    $(document).find('[data-i18n]').each(function () {

        let el = $(this), key = el.data('i18n').toLowerCase();
        
        if (data[key]) {
            el.text(data[key]);
        }
    });
}
