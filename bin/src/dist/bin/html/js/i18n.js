


async function i18n(config) {

    let data = await $.getJSON('i18n/' + config.locale + '.json');

    for(let key in data){

        data[key.toLowerCase()] = data[key];
    }

    $(document).find('[data-i18n]').each(function () {

        let el = $(this), key = el.data('i18n').toLowerCase();
        
        if (data[key]) {
            el.text(data[key]);
        }
    });
}