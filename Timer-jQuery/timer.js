/**
 * Created with JetBrains PhpStorm.
 * User: cyril928
 * Date: 2013/1/20
 * Time: 上午 10:22
 * To change this template use File | Settings | File Templates.
 */

function timer(inputFrom, inputTo, inputToday, inputClear){
    var oneDay = 24*60*60*1000;
    var oneWeek = oneDay*7;
    var oneYear = oneDay*365;
    var rangeTimeFormat = "%Y-%b-%d %H:%i";
    var rangeTimeConv = new AnyTime.Converter({format:rangeTimeFormat});
    $(inputToday).click( function(e) {
        $(inputTo).val(rangeTimeConv.format(new Date())).change(); } );
    $(inputClear).click( function(e) {
        $(inputTo).val("").change(); } );
    $(inputTo).AnyTime_picker({format:rangeTimeFormat});
    $(inputTo).change( function(e) { try {

        var ToDay = rangeTimeConv.parse($(inputTo).val()).getTime();

        var oneDayFormer = new Date(ToDay-oneDay);
        oneDayFormer.setSeconds(0);
        var oneWeekFormer = new Date(ToDay-oneWeek);
        oneWeekFormer.setSeconds(0);
        var oneYearFormer = new Date(ToDay-oneYear);
        oneYearFormer.setSeconds(0);

        var inputFromValue;
        if($(inputFrom).val()== "") {
            inputFromValue = oneDayFormer;
        }
        else {
            var FromDay = rangeTimeConv.parse($(inputFrom).val()).getTime();
            if(ToDay > FromDay)
                inputFromValue = new Date(FromDay);
            else
                inputFromValue = oneDayFormer;
        }
        inputFromValue.setSeconds(0);
        //console.log(inputFromValue);
        $(inputFrom).
            AnyTime_noPicker().
            removeAttr("disabled").
            val(rangeTimeConv.format(inputFromValue)).
            AnyTime_picker(
            { earliest: oneYearFormer,
                format: rangeTimeFormat,
                latest: oneDayFormer
            } );
    } catch(e){ $(inputFrom).val("").attr("disabled","disabled"); } } );


}

function initDefaultTime(inputID){
    var rangeTimeFormat = "%Y-%b-%d %H:%i";
    var rangeTimeConv = new AnyTime.Converter({format:rangeTimeFormat});
    $(inputID).val(rangeTimeConv.format(new Date())).change();
}

function initUserTime(fromInputID, toInputID, fromTime, toTime){
    // rangeTimeFormat and AnyTime_picker are used to activate the time picker in the rangeTimeFrom inputform
    var rangeTimeFormat = "%Y-%b-%d %H:%i";
    $(fromInputID).AnyTime_picker({format:rangeTimeFormat}).val(fromTime);
    $(toInputID).val(toTime);
}
