import datetime as dt
from dateutil.relativedelta import relativedelta
import pandas as pd
import sys
import re
import numpy as np

patchExclusionList = ['ARM', 'arm', 'Embedded', '팜', '팝', 'Itanium', 'POS']
officeList = ['Office', 'Word', 'Excel', 'Outlook', 'PowerPoint', 'Visio', 'SharePoint']

"""
#v# : Version
#ki# : KBID
#gi# : GUID
#s# : Severity
"""
totalRegexDic = {
    'windows-cumulative' : [
        {
            'regex' : 'x86 기반 시스템용 Windows 10 Version \w{4}에 대한 누적 업데이트',
            'excel' : '	Q#ki# 10_#v#	#gi#	#ki#	0	W10		#df1#	#df2#, Windows 10 #v# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#v#-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [
                {
                    'match' : '#v#',
                    'startIndex' : 'Version ',
                    'offset' : 8,
                    'endIndex' : '에 대한'
                }
            ],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 10 Version \w{4}에 대한 누적 업데이트',
            'excel' : '	Q#ki# 10_#v#_x64	#gi#	#ki#	9	W10		#df1#	#df2#, Windows 10_x64 #v# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#v#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [
                {
                    'match' : '#v#',
                    'startIndex' : 'Version ',
                    'offset' : 8,
                    'endIndex' : '에 대한'
                }
            ],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11 Version \w{4}에 대한 누적 업데이트',
            'excel' : '	Q#ki# 11_#v#_x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11 #v# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-#v#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [
                {
                    'match' : '#v#',
                    'startIndex' : 'Version ',
                    'offset' : 8,
                    'endIndex' : '에 대한'
                }
            ],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11에 대한 누적 업데이트',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 10 Version \w{4} for x86-based Systems',
            'excel' : '	Q#ki# 10_#v#	#gi#	#ki#	0	W10		#df1#	#df2#, Windows 10 #v# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows10.0-#v#-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [
                {
                    'match' : '#v#',
                    'startIndex' : 'Version ',
                    'offset' : 8,
                    'endIndex' : ' for x86'
                }
            ],
            'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 10 Version \w{4} for x64-based Systems',
            'excel' : '	Q#ki# 10_#v#_x64	#gi#	#ki#	9	W10		#df1#	#df2#, Windows 10_x64 #v# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows10.0-#v#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [
                {
                    'match' : '#v#',
                    'startIndex' : 'Version ',
                    'offset' : 8,
                    'endIndex' : ' for x64'
                }
            ],
            'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 11 Version \w{4} for x64-based Systems',
            'excel' : '	Q#ki# 11_#v#x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11_x64 #v# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows11.0-#v#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [
                {
                    'match' : '#v#',
                    'startIndex' : 'Version ',
                    'offset' : 8,
                    'endIndex' : ' for x64'
                }
            ],
            'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 11 for x64-based Systems',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11_x64 Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2016에 대한 누적 업데이트',
            'excel' : '	Q#ki# 216	#gi#	#ki#	9	W216		#df1#	#df2#, Windows 2016_x64 누적 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows10.0-1607-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2019에 대한 누적 업데이트',
            'excel' : '	Q#ki# 219	#gi#	#ki#	9	W219		#df1#	#df2#, Windows 2019_x64 누적 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows10.0-1809-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        }
    ],
    'windows-security' : [
        {
            'regex' : 'x86 기반 시스템용 Windows Server 2008에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 28	#gi#	#ki#	0	W28		#df1#	#df2#, Windows 2008 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.0-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows Server 2008에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 28	#gi#	#ki#	0	W28		#df1#	#df2#, Windows 2008 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.0-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 7에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7		#df1#	#df2#, Windows 7 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 7에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7		#df1#	#df2#, Windows 7 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 8.1에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 81	#gi#	#ki#	0	W81		#df1#	#df2#, Windows 8.1 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 8.1에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	#df2#, Windows 8.1_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 28_x64	#gi#	#ki#	9	W28		#df1#	#df2#, Windows 2008_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 28_x64	#gi#	#ki#	9	W28		#df1#	#df2#, Windows 2008_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 7에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7		#df1#	#df2#, Windows 7_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 7에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7		#df1#	#df2#, Windows 7_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 8.1에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	#df2#, Windows 8.1_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 8.1에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	#df2#, Windows 8.1_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008 R2에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2		#df1#	#df2#, Windows 2008R2_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008 R2에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2		#df1#	#df2#, Windows 2008R2_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212		#df1#	#df2#, Windows 2012 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8-RT-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212		#df1#	#df2#, Windows 2012 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8-RT-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012 R2에 대한 보안 전용 품질 업데이트',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2		#df1#	#df2#, Windows 2012R2 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012 R2에 대한 보안 월별 품질 롤업',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2		#df1#	#df2#, Windows 2012R2 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 10 Version 22H2 보안 업데이트',
            'excel' : '	Q#ki# 10_22H2	#gi#	#ki#	0	W10		#df1#	#df2#, Windows 10 22H2 보안 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows10.0-22H2-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 2
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 10 Version 22H2 보안 업데이트',
            'excel' : '	Q#ki# 10_22H2_x64	#gi#	#ki#	9	W10		#df1#	#df2#, Windows 10_x64 22H2 보안 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows10.0-22H2-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 2
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11 22H2 보안 업데이트',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11 보안 업데이트	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'replaceList' : [],
            'group' : 2
        }
    ]
}

totalRowDic = {
    'windows-cumulative' : {},
    'windows-security' : {}
}
undecidedList = []

startPeriod = None
endPeriod = None

importantSet = set()
criticalSet = set()

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

def makeSeveritySet():
    global importantSet
    global criticalSet

    xlsPath = "./Security Updates " + endPeriod.strftime('%Y-%m-%d') + '.csv'

    securityUpdates = pd.read_csv(xlsPath, encoding = 'ANSI')
    securityUpdates = securityUpdates.rename(columns={"Max Severity":"Severity"})

    for i in range(len(securityUpdates.Severity)):
        if securityUpdates.Article[i].isdigit():
            if securityUpdates.Severity[i] is not None:
                if('Important' == securityUpdates.Severity[i]):
                    importantSet.add(str(securityUpdates.Article[i]))
                elif('Critical' == securityUpdates.Severity[i]):
                    criticalSet.add(str(securityUpdates.Article[i]))
            
    importantSet = importantSet.difference(criticalSet)

def setSeverity(excelStr, kbid):
    severityStr = ''
    if kbid in criticalSet:
        severityStr = '1'
    elif kbid in importantSet:
        severityStr = '0'
    return excelStr.replace('#s#', severityStr)


def addPatchRow(Classification, guid, kbid, des):
    global endPeriod
    regexList = totalRegexDic[Classification]
    for regexDic in regexList:
        regexPattern = re.compile(regexDic['regex'])
        result = regexPattern.search(des)
        if result:
            excelStr = regexDic['excel']
            # KBID, GUID, dateForm1, dateForm2 적용
            excelStr = excelStr.replace('#ki#', kbid).replace('#gi#', guid).replace('#df1#', endPeriod.strftime('%Y-%m-%d')).replace('#df2#', endPeriod.strftime('%Y년 %m월'))
            # 개별 변경 사항 적용
            for one in regexDic['replaceList']:
                startIndex = des.find(one['startIndex']) + one['offset']
                endIndex = des.find(one['endIndex'])
                replaceStr = des[startIndex:endIndex]
                excelStr = excelStr.replace(one['match'], replaceStr)
            # 심각도(Severity) 적용
            excelStr = setSeverity(excelStr, kbid)
            # 최종행 저장
            if regexDic['group'] in totalRowDic[Classification]:
                totalRowDic[Classification][regexDic['group']].append(excelStr)
            else:
                totalRowDic[Classification][regexDic['group']] = [excelStr]

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
        if any(one in des for one in ['누적', 'Cumulative']):
            addPatchRow('windows-cumulative', guid, kbid, des)
        else:
            addPatchRow('windows-security', guid, kbid, des)
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

    makeSeveritySet()

    patchList = readPatchListFromExcel()
    writePatchListToExcel(patchList)

main()