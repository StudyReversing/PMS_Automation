import datetime as dt
from dateutil.relativedelta import relativedelta
import pandas as pd
import sys
import re

patchExclusionList = ['ARM', 'arm', 'Embedded', '팜', '팝', 'Itanium', 'POS']
officeList = ['Office', 'Word', 'Excel', 'Outlook', 'PowerPoint', 'Visio', 'SharePoint']

totalRegexDic = {
    'windows' : [
        {
            'regex' : 'x86 기반 시스템용 Windows 10 Version \w{4}에 대한 누적 업데이트',
            'excel' : '	Q#kbid# 10_1507	#guid#	#kbid#	0	W10		#df1#	#df2#, Windows 10 #version# 누적 업데이트	http://support.microsoft.com/kb/#kbid#	0	0	Microsoft			1	Windows10.0-#version#-KB#kbid#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [
                {
                    'match' : '#version#',
                    'startIndex' : 'Version ',
                    'offset' : 8,
                    'endIndex' : '에 대한'
                }
            ],
            'group' : 1
        }
    ]  
}

totalRowDic = {
    'windows' : {
        1 : [],
        2 : []
    }
}
undecidedList = []

startPeriod = None
endPeriod = None

def getPatchPeriod():
    global startPeriod
    global endPeriod
    today = dt.date.today()
    beforeOneMonth = today - relativedelta(months=1)
    startPeriod = getPatchDateByMonth(beforeOneMonth)
    endPeriod = getPatchDateByMonth(today)

def getPatchDateByMonth(dateTime):
    patchDate = dateTime.replace(day=1)
    weeks = 0
        
    while weeks < 2:
        if patchDate.weekday() == 1:
            weeks += 1
        patchDate += dt.timedelta(days=1)

    return patchDate

def isPatchExclusion(des):
    return any(one in des for one in patchExclusionList)

def validatePatchInfo(kbid, des):
    if not isinstance(kbid, float) or kbid == 0:
        return False
    if not isinstance(des, str) or isPatchExclusion(des):
        return False
    return True

def addPatchRow(Classification, guid, kbid, des):
    global endPeriod
    regexList = totalRegexDic[Classification]
    for regexDic in regexList:
        regexPattern = re.compile(regexDic['regex'])
        result = regexPattern.search(des)
        if result:
            excelStr = regexDic['excel']
            excelStr = excelStr.replace('#kbid#', kbid).replace('#guid#', guid).replace('#df1#', endPeriod.strftime('%Y-%m-%d')).replace('#df2#', endPeriod.strftime('%Y년 %m월'))
            for one in regexDic['replaceList']:
                startIndex = des.find(one['startIndex']) + one['offset']
                endIndex = des.find(one['endIndex'])
                replaceStr = des[startIndex:endIndex]
                excelStr = excelStr.replace(one['match'], replaceStr)
            totalRowDic[Classification][regexDic['group']].append(excelStr)
            return
    undecidedList.append([guid, kbid, des])

def createPatchRows(guid, kbid, des):
    if '.Net' in des or '.NET' in des:
        None
    elif 'Azure' in des:
        None
    elif 'Internet' in des:
        None
    elif 'Windows' in des:
        addPatchRow('windows', guid, kbid, des)
    elif 'Exchange' in des:
        None
    elif 'PowerShell' in des:
        None
    elif any(one in des for one in officeList):
        None
    else:
        None

def readPatchListFromExcel():
    global endPeriod
    xlsPath = './' + endPeriod.strftime('%Y_%m_%d') + '_Result.csv'
    patchList = pd.read_csv(xlsPath, encoding = 'ANSI', names=['day', 'GUID', 'c', 'd', 'KBID', 'Des'])
    if patchList.shape[0] < 1: # == len(patchTargetList)
        print('패치 목록을 불러오는데 실패했습니다.')
        sys.exit()
    else:
        return patchList
    
def writePatchListToExcel(patchList):
    global startPeriod
    global endPeriod
    for i in reversed(range(patchList.shape[0])):
        try:
            row_datetime = dt.datetime.strptime(patchList.day[i], '%Y-%m-%dT%H:%M:%SZ').date()
            if row_datetime >= endPeriod:
                continue
            elif row_datetime < startPeriod:
                break
            else:
                if validatePatchInfo(patchList.KBID[i], patchList.Des[i]):
                    createPatchRows(patchList.GUID[i], str(int(patchList.KBID[i])), patchList.Des[i])
        except ValueError as e: # 날짜영역에 문자열이 들어있는 경우
            print('ValueError' ,e)
        except TypeError as e:  # 날짜영역이 비어있는 경우
            print('TypeError', e)

    return None

def main():
    global startPeriod
    global endPeriod
    numberOfArgs = len(sys.argv)
    if numberOfArgs == 1:
        getPatchPeriod()
    elif numberOfArgs == 3:
        startPeriod, endPeriod = dt.datetime.strptime(sys.argv[1], '%Y%m%d').date(), dt.datetime.strptime(sys.argv[2], '%Y%m%d').date()
    else:
        print('파라미터 개수를 확인해주세요.')
        sys.exit()

    patchList = readPatchListFromExcel()
    writePatchListToExcel(patchList)

main()