import datetime as dt
from dateutil.relativedelta import relativedelta
import pandas as pd
import sys
import re

patchExclusionList = ['ARM', 'arm', 'Embedded', '팜', '팝', 'Itanium', 'POS']
officeList = ['Office', 'Word', 'Excel', 'Outlook', 'PowerPoint', 'Visio', 'SharePoint']

totalRegexDic = {
    'windows' : {
        'cumulative' : [
            {
                'regex' : 'x86 기반 시스템용 Windows 10 Version \w{4}에 대한 누적 업데이트',
                'excel' : '	Q#kbid# 10_1507	#guid#	#kbid#	0	W10		#df1#	#df2#, Windows 10 #version# 누적 업데이트	http://support.microsoft.com/kb/#kbid#	0	0	Microsoft			1	Windows10.0-#version#-KB#kbid#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
                'replaceList' : [
                    {
                        'match' : '#version#',
                        'findStr' : 'Version ',
                        'offset' : 8,
                        'length' : 4
                    }
                ]
            }
        ],
        'security' : [
            
        ]
    }
}

totalRowDic = {
    'windows' : {
        'cumulative' : [],
        'security' : []
    }
}
undecidedList = []

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

def isPatchExclusion(des):
    for one in patchExclusionList:
        if one in des:
            return True
    return False

def validatePatchInfo(kbid, des):
    if not isinstance(kbid, float) or kbid == 0:
        return False
    if not isinstance(des, str) or isPatchExclusion(des):
        return False
    return True

def addPatchRow(depth1, guid, kbid, des, endPeriod):
    regexDic = totalRegexDic[depth1]
    for dicKey in regexDic:
        for atomDic in regexDic[dicKey]:
            regexPattern = re.compile(atomDic['regex'])
            result = regexPattern.search(des)
            if result:
                print('Match found : ', result.group())
                excelStr = atomDic['excel']
                excelStr = excelStr.replace('#kbid#', kbid).replace('#guid#', guid).replace('#df1#', endPeriod.strftime('%Y-%m-%d')).replace('#df2#', endPeriod.strftime('%Y년 %m월'))
                for one in atomDic['replaceList']:
                    findIndex = des.find(one['findStr'])
                    offset = one['offset']
                    replaceStr = des[findIndex+offset:findIndex+offset+one['length']]
                    excelStr = excelStr.replace(one['match'], replaceStr)
                totalRowDic[depth1][dicKey].append(excelStr)
                return
    undecidedList.append([guid, kbid, des])

def createPatchRows(guid, kbid, des, endPeriod):
    if '.Net' in des or '.NET' in des:
        None
    elif 'Azure' in des:
        None
    elif 'Internet' in des:
        None
    elif 'Windows' in des:
        addPatchRow('windows', guid, kbid, des, endPeriod)
    elif 'Exchange' in des:
        None
    elif 'PowerShell' in des:
        None
    elif any(one in des for one in officeList):
        None
    else:
        None

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
                if validatePatchInfo(patchList.KBID[i], patchList.Des[i]):
                    createPatchRows(patchList.GUID[i], str(int(patchList.KBID[i])), patchList.Des[i], endPeriod)
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
        startPeriod, endPeriod = dt.datetime.strptime(sys.argv[1], '%Y%m%d').date(), dt.datetime.strptime(sys.argv[2], '%Y%m%d').date()
    else:
        print('파라미터 개수를 확인해주세요.')
        sys.exit()

    patchList = readPatchListFromExcel(endPeriod)
    writePatchListToExcel(patchList, startPeriod, endPeriod)

main()