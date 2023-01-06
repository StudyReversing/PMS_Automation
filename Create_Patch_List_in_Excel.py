import datetime as dt
from dateutil.relativedelta import relativedelta
import sys

def getPatchPeriod():
    today = dt.date.today()
    beforeOneMonth = today - relativedelta(months=1)
    startPeriod = getPatchDateByMonth(beforeOneMonth)
    endPeriod = getPatchDateByMonth(today)
    return startPeriod, endPeriod

def getPatchDateByMonth(dateTime):
    patchDate = dateTime.replace(day=1)
    weeks = 0
        
    while weeks < 2:
        if patchDate.weekday() == 1:
            weeks += 1
        patchDate += dt.timedelta(days=1)

    return patchDate

def main():
    numberOfArgs = len(sys.argv)
    if numberOfArgs == 1:
        startPeriod, endPeriod = getPatchPeriod()
    elif numberOfArgs == 3:
        startPeriod, endPeriod = sys.argv[1], sys.argv[2]
    else:
        print('파라미터 개수를 확인해주세요.')
        sys.exit()

main()