import datetime as dt
from dateutil.relativedelta import relativedelta
import pandas as pd
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

def readPatchListFromExcel(patchDateTime):
    xlsPath = './' + patchDateTime.strftime('%Y_%m_%d') + '_Result.csv'
    patchList = pd.read_csv(xlsPath, encoding = 'ANSI', names=['day', 'GUID', 'c', 'd', 'KBID', 'Des'])
    if patchList.shape[0] < 1: # == len(patchTargetList)
        print('패치 목록을 불러오는데 실패했습니다.')
        sys.exit()
    else:
        return patchList
    
def writePatchListToExcel(patchList, startPeriod, endPeriod):
    for i in reversed(range(patchList.shape[0])):
        try:
            row_datetime = dt.datetime.strptime(patchList.day[i], '%Y-%m-%dT%H:%M:%SZ').date()
            if row_datetime >= endPeriod:
                continue
            elif row_datetime < startPeriod:
                break
            else:
                return None
        except ValueError as e: # 날짜영역에 문자열이 들어있는 경우
            print('ValueError' ,e)
        except TypeError as e:  # 날짜영역이 비어있는 경우
            print('TypeError', e)
        
    return None

def main():
    numberOfArgs = len(sys.argv)
    if numberOfArgs == 1:
        startPeriod, endPeriod = getPatchPeriod()
    elif numberOfArgs == 3:
        startPeriod, endPeriod = sys.argv[1], sys.argv[2]
    else:
        print('파라미터 개수를 확인해주세요.')
        sys.exit()

    patchList = readPatchListFromExcel(endPeriod)
    writePatchListToExcel(patchList, startPeriod, endPeriod)

main()