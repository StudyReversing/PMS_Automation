patchExclusionList = ['ARM', 'arm', 'Embedded', '팜', '팝', 'Itanium', 'POS', 'Visual Studio']
officeList = ['Office', 'Word', 'Excel', 'Outlook', 'PowerPoint', 'Visio', 'Publisher', 'SharePoint']

"""
#ki# : KBID
#gi# : GUID
#s# : Severity
#fn# : FileName
#dv# : DotNetVersion
"""
totalRegexDic = {
    'windows-cumulative' : [
        {
            'regex' : 'x86 기반 시스템용 Windows 10 Version (\w{4})에 대한 누적',
            'excel' : '	Q#ki# 10_#1#	#gi#	#ki#	0	W10		#df1#	Windows 10 #1# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descriptionInEnglish' : 'Windows 10 #1# Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 10 Version (\w{4})에 대한 누적',
            'excel' : '	Q#ki# 10_#1#_x64	#gi#	#ki#	9	W10		#df1#	Windows 10_x64 #1# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descriptionInEnglish' : 'Windows 10_x64 #1# Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11 Version (\w{4})에 대한 누적',
            'excel' : '	Q#ki# 11_#1#_x64	#gi#	#ki#	9	W11		#df1#	Windows 11 #1# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descriptionInEnglish' : 'Windows 11_x64 #1# Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11에 대한 누적',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	Windows 11 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descriptionInEnglish' : 'Windows 11_x64 Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2016에 대한 누적',
            'excel' : '	Q#ki# 216	#gi#	#ki#	9	W216		#df1#	Windows 2016_x64 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-1607-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 2016_x64 Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2019에 대한 누적',
            'excel' : '	Q#ki# 219	#gi#	#ki#	9	W219		#df1#	Windows 2019_x64 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-1809-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 2019_x64 Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 10 Version (\w{4}) for x86',
            'excel' : '	Q#ki# 10_#1#	#gi#	#ki#	0	W10		#df1#	Windows 10 #1# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descriptionInEnglish' : 'Windows 10 #1# Dynamic Cumulative update',
            'group' : 2
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 10 Version (\w{4}) for x64',
            'excel' : '	Q#ki# 10_#1#_x64	#gi#	#ki#	9	W10		#df1#	Windows 10_x64 #1# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 10_x64 22H2 Dynamic Cumulative update',
			'group' : 2
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 11 Version (\w{4}) for x64',
            'excel' : '	Q#ki# 11_#1#x64	#gi#	#ki#	9	W11		#df1#	Windows 11_x64 #1# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 11_x64 #1# Dynamic Cumulative update',
			'group' : 2
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 11 for x64',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	Windows 11_x64 Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 11 Dynamic Cumulative update',
			'group' : 2
        }
    ],
    'windows-security' : [
        {
            'regex' : 'x86 기반 시스템용 Windows Server 2008에 대한 보안 전용',
            'excel' : '	Q#ki# 28	#gi#	#ki#	0	W28		#df1#	Windows 2008 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.0-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 2008 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x86 기반 시스템용 Windows Server 2008에 대한 보안 월별',
            'excel' : '	Q#ki# 28	#gi#	#ki#	0	W28		#df1#	Windows 2008 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.0-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 2008 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 7에 대한 보안 전용',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7		#df1#	Windows 7 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 7 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x86 기반 시스템용 Windows 7에 대한 보안 월별',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7		#df1#	Windows 7 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 7 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 8.1에 대한 보안 전용',
            'excel' : '	Q#ki# 81	#gi#	#ki#	0	W81		#df1#	Windows 8.1 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 8.1 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x86 기반 시스템용 Windows 8.1에 대한 보안 월별',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	Windows 8.1_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 8.1 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008에 대한 보안 전용',
            'excel' : '	Q#ki# 28_x64	#gi#	#ki#	9	W28		#df1#	Windows 2008_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 2008_x64 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x64 기반 시스템용 Windows Server 2008에 대한 보안 월별',
            'excel' : '	Q#ki# 28_x64	#gi#	#ki#	9	W28		#df1#	Windows 2008_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 2008_x64 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 7에 대한 보안 전용',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7		#df1#	Windows 7_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 7_x64 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x64 기반 시스템용 Windows 7에 대한 보안 월별',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7		#df1#	Windows 7_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 7_x64 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 8.1에 대한 보안 전용',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	Windows 8.1_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 8.1_x64 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x64 기반 시스템용 Windows 8.1에 대한 보안 월별',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	Windows 8.1_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 8.1_x64 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008 R2에 대한 보안 전용',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2		#df1#	Windows 2008R2_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 2008R2_x64 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x64 기반 시스템용 Windows Server 2008 R2에 대한 보안 월별',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2		#df1#	Windows 2008R2_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 2008R2_x64 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012에 대한 보안 전용',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212		#df1#	Windows 2012 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8-RT-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 2012 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x64 기반 시스템용 Windows Server 2012에 대한 보안 월별',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212		#df1#	Windows 2012 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8-RT-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 2012 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012 R2에 대한 보안 전용',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2		#df1#	Windows 2012R2 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 2012R2 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x64 기반 시스템용 Windows Server 2012 R2에 대한 보안 월별',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2		#df1#	Windows 2012R2 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Windows 2012R2 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 10 Version 22H2 보안',
            'excel' : '	Q#ki# 10_22H2	#gi#	#ki#	0	W10		#df1#	Windows 10 22H2 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-22H2-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descriptionInEnglish' : 'Security update for Windows 10 22H2',
            'group' : 2
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 10 Version 22H2 보안',
            'excel' : '	Q#ki# 10_22H2_x64	#gi#	#ki#	9	W10		#df1#	Windows 10_x64 22H2 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-22H2-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descriptionInEnglish' : 'Security update for Windows 10_x64 22H2',
            'group' : 2
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11 22H2 보안',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	Windows 11 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descriptionInEnglish' : 'Security update for Windows 11',
            'group' : 2
        }
    ],
    'windows-etc' : [
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012에 대한 서비스 스택',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212		#df1#	Windows 2012 서비스 스택 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8-RT-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descriptionInEnglish' : 'Windows Server 2012 Servicing stack update',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2016에 대한 서비스 스택',
            'excel' : '	Q#ki# 216	#gi#	#ki#	9	W219		#df1#	Windows 2016_x64 서비스 스택 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-1607-KB#ki#-x64-KOR.msu	1				',
            'descriptionInEnglish' : 'Windows 2016_x64 Servicing stack update',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012 R2에 대한 서비스 스택',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2		#df1#	Windows 2012R2 서비스 스택 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descriptionInEnglish' : 'Windows 2012R2 Servicing stack update',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 10 Version 1507에 대한 서비스 스택',
            'excel' : '	Q#ki# 10_1507_x64	#gi#	#ki#	9	W10		#df1#	Windows 10_x64 1507 서비스 스택 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-1507-KB#ki#-x64-KOR.msu	1				',
            'descriptionInEnglish' : 'Windows 10_x64 1507 Servicing stack update',
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 10 Version 1507에 대한 서비스 스택',
            'excel' : '	Q#ki# 10_1507	#gi#	#ki#	0	W10		#df1#	Windows 10 1507 서비스 스택 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-1507-KB#ki#-x86-KOR.msu	1				',
            'descriptionInEnglish' : 'Windows 10 1507 Servicing stack update',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 10 Version 1607에 대한 서비스 스택',
            'excel' : '	Q#ki# 10_1607_x64	#gi#	#ki#	9	W10		#df1#	Windows 10_x64 1607 서비스 스택 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-1607-KB#ki#-x64-KOR.msu	1				',
            'descriptionInEnglish' : 'Windows 10_x64 1607 Servicing stack update',
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 10 Version 1607에 대한 서비스 스택',
            'excel' : '	Q#ki# 10_1607	#gi#	#ki#	0	W10		#df1#	Windows 10 1607 서비스 스택 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-1607-KB#ki#-x86-KOR.msu	1				',
            'descriptionInEnglish' : 'Windows 10 1607 Servicing stack update',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 8.1에 대한 서비스 스택',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	Windows 8.1_x64 서비스 스택 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descriptionInEnglish' : 'Windows 8.1_x64 Servicing stack update',
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 8.1에 대한 서비스 스택',
            'excel' : '	Q#ki# 81	#gi#	#ki#	0	W81		#df1#	Windows 8.1 서비스 스택 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descriptionInEnglish' : 'Windows 8.1 Servicing stack update',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 7에 대한 서비스 스택',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7		#df1#	Windows 7_x64 서비스 스택 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1				',
            'descriptionInEnglish' : 'Windows 7_x64 Servicing stack update',
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 7에 대한 서비스 스택',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7		#df1#	Windows 7 서비스 스택 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x86-KOR.msu	1				',
            'descriptionInEnglish' : 'Windows 7 Servicing stack update',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008 R2에 대한 서비스 스택',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2		#df1#	Windows 2008R2_x64 서비스 스택 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1				',
            'descriptionInEnglish' : 'Windows 2008R2_x64 Servicing stack update',
            'group' : 1
        }
    ],
    "office" : [
        {
            'regex' : 'Microsoft Office 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSO213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Office 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	oart2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Office 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Office 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSO213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Office 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	oart2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Office 2013_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Office 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSO216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Office 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	oart2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Office 2016',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Office 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSO216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Office 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	oart2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Office 2016_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Word 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSW213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Word 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	word2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Word 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Word 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSW213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Word 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	word2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Word 2013_64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Word 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSW216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Word 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	word2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Word 2016',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Word 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSW216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Word 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	word2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Word 2016_64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Excel 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MOE213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Excel 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	excel2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Excel 2013 ',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Excel 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MOE213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Excel 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	excel2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Excel 2013_x64 ',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Excel 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MOE216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Excel 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	excel2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Excel 2016 ',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Excel 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MOE216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Excel 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	excel2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Excel 2016_x64 ',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Outlook 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSOO213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Outlook 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	outlook2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Outlook 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Outlook 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSOO213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Outlook 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	outlook2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Outlook 2013_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Outlook 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSOO216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Outlook 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	outlook2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Outlook 2016',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Outlook 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSOO216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Outlook 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	outlook2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Outlook 2016_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft PowerPoint 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSPP213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft PowerPoint 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	powerpoint2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft PowerPoint 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft PowerPoint 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSPP213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft PowerPoint 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	powerpoint2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft PowerPoint 2013_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft PowerPoint 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSPP216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft PowerPoint 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	powerpoint2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft PowerPoint 2016',
			'group' : 1
        },
        {
            'regex' : 'Microsoft PowerPoint 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSPP216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft PowerPoint 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	powerpoint2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft PowerPoint 2016_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Visio 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MV213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Visio 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	visio2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Visio 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Visio 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MV213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Visio 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	visio2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Visio 2013_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Visio 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MV216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Visio 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	visio2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Visio 2016',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Visio 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MV216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Visio 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	visio2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Visio 2016_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Publisher 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MP213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Publisher 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	publisher2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Publisher 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Publisher 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MP213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Publisher 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	publisher2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Publisher 2013_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Publisher 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MP216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Publisher 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	publisher2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Publisher 2016',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Publisher 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MP216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Publisher 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	publisher2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Publisher 2016_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft SharePoint Foundation 2013용 보안',
            'excel' : '	Q#ki# MSSPF213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W81,W212,W212R2,W10,W216		#df1#	Microsoft SharePoint Foundation 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	sts2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft SharePoint Foundation 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft SharePoint Enterprise Server 2013용 보안',
            'excel' : '	Q#ki# MSSPS213	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W81,W212,W212R2,W10,W216		#df1#	Microsoft SharePoint Enterprise Server 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	coreserverloc2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft SharePoint Enterprise Server 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Office Web Apps Server 2013용 보안',
            'excel' : '	Q#ki# MSOWAS213	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W81,W212,W212R2,W10,W216		#df1#	Microsoft Office Web Apps Server 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	wacserver2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Office Web Apps Server 2013',
			'group' : 1
        }
    ],
    'dotnet' : [
        {
            'regex' : 'x64용 Windows 10 Version (\w{4})용 .NET Framework (.+) 누적',
            'excel' : '	Q#ki# 10_#1#_x64	#gi#	#ki#	9	W10		#df1#	Windows 10 #1#_x64 .NET Framework #dv# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'windows10.0-kb(\d{7})-x64-ndp48_',
                    'excel' : 'Windows10.0-#1#-KB#f1#-NDP48-x64-KOR.msu'
                },
                {
                    'regex' : 'windows10.0-kb(\d{7})-x64-ndp481',
                    'excel' : 'Windows10.0-#1#-KB#f1#-NDP481-x64-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Cumulative Update for Windows 10 #1#_x64 .NET Framework #dv#',
			'group' : 1
        },
        {
            'regex' : 'Windows 10 Version (\w{4})용 .NET Framework (.+) 누적',
            'excel' : '	Q#ki# 10_#1#	#gi#	#ki#	0	W10		#df1#	Windows 10 #1# .NET Framework #dv# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'windows10.0-kb(\d{7})-x86-ndp48_',
                    'excel' : 'Windows10.0-#1#-KB#f1#-NDP48-x86-KOR.msu'
                },
                {
                    'regex' : 'windows10.0-kb(\d{7})-x86-ndp481',
                    'excel' : 'Windows10.0-#1#-KB#f1#-NDP481-x86-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Cumulative Update for Windows 10 #1# .NET Framework #dv#',
			'group' : 1
        },
        {
            'regex' : 'x64의 Windows 10 Version (\d{4}) 용 .NET Framework (.+) 누적',
            'excel' : '	Q#ki# 10_#1#_x64	#gi#	#ki#	9	W10		#df1#	Cumulative Update for .NET Framework #dv# for Windows 10 Version #1# for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'windows10.0-kb(\d{7})-x64_',
                    'excel' : 'Windows10.0-#1#-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'windows10.0-kb(\d{7})-x64-',
                    'excel' : 'Windows10.0-#1#-KB#f1#-x64-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Cumulative Update for .NET Framework #dv# for Windows 10 Version #1# for x64',
			'group' : 2
        },
        {
            'regex' : 'Windows 10 Version (\d{4}) 용 .NET Framework (.+) 누적',
            'excel' : '	Q#ki# 10_#1#	#gi#	#ki#	0	W10		#df1#	Cumulative Update for .NET Framework #dv# for Windows 10 Version #1#	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'windows10.0-kb(\d{7})-x86_',
                    'excel' : 'Windows10.0-#1#-KB#f1#-x86-KOR.msu'
                },
                {
                    'regex' : 'windows10.0-kb(\d{7})-x86-',
                    'excel' : 'Windows10.0-#1#-KB#f1#-x86-NDP48-KOR.msu'
                }
            ],
            'descriptionInEnglish' : 'Cumulative Update for .NET Framework #dv# for Windows 10 Version #1#',
			'group' : 2
        },
        {
            'regex' : 'Windows 10 Version (\d{4})에 대한 .NET Framework (.+) 누적',
            'excel' : '	Q#ki# 10_#1#	#gi#	#ki#	0	W10		#df1#	Cumulative Update for .NET Framework #dv# for Windows 10 Version #1#	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'windows10.0-kb(\d{7})-x86_',
                    'excel' : 'Windows10.0-#1#-KB#f1#-x86-KOR.msu'
                },
                {
                    'regex' : 'windows10.0-kb(\d{7})-x86-',
                    'excel' : 'Windows10.0-#1#-KB#f1#-x86-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Cumulative Update for .NET Framework #dv# for Windows 10 Version #1#',
			'group' : 2
        },
        {
            'regex' : 'Windows 10 Version (\d{4}) x64에 대한 .NET Framework (.+) 누적',
            'excel' : '	Q#ki# 10_#1#_x64	#gi#	#ki#	9	W10		#df1#	Cumulative Update for .NET Framework #dv# for Windows 10 Version #1# for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'windows10.0-kb(\d{7})-x64_',
                    'excel' : 'Windows10.0-#1#-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'windows10.0-kb(\d{7})-x64-',
                    'excel' : 'Windows10.0-#1#-KB#f1#-x64-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Cumulative Update for .NET Framework #dv# for Windows 10 Version #1# for x64',
			'group' : 2
        },
        {
            'regex' : 'x64의 Windows Server 2016 용 .NET Framework (.+) 누적',
            'excel' : '	Q#ki# 216	#gi#	#ki#	9	W216		#df1#	Cumulative Update for .NET Framework #dv# for Windows Server 2016 for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'windows10.0-kb(\d{7})-x64-ndp48_',
                    'excel' : 'Windows10.0-1607-KB#f1#-x64-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Cumulative Update for .NET Framework #dv# for Windows Server 2016 for x64',
			'group' : 2
        },
        {
            'regex' : 'Windows Server 2019 x64에 대한 .NET Framework (.+) 누적',
            'excel' : '	Q#ki# 219	#gi#	#ki#	9	W219		#df1#	Cumulative Update for .NET Framework #dv# for Windows Server 2019 for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'windows10.0-kb(\d{7})-x64_',
                    'excel' : 'Windows10.0-1809-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'windows10.0-kb(\d{7})-x64-ndp48_',
                    'excel' : 'Windows10.0-1809-KB#f1#-x64-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Cumulative Update for .NET Framework #dv# for Windows Server 2019 for x64',
			'group' : 2
        },
        {
            'regex' : 'Windows 11용 .NET Framework (.+) 누적',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	Cumulative Update for .NET Framework #dv# for Windows 11 for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'windows11.0-kb(\d{7})-x64-ndp481_',
                    'excel' : 'Windows11.0-KB#f1#-x64-NDP481-KOR.msu'
                },
                {
                    'regex' : 'windows10.0-kb(\d{7})-x64-ndp48_',
                    'excel' : 'Windows10.0-KB#f1#-x64-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Cumulative Update for .NET Framework #dv# for Windows 11 for x64',
			'group' : 2
        },
        {
            'regex' : 'Windows 11  version 22H2 x64에 대한 .NET Framework (.+) 누적',
            'excel' : '	Q#ki# 11_22H2_x64	#gi#	#ki#	9	W11		#df1#	Cumulative Update for .NET Framework #dv# for Windows 11_22H2 for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'windows11.0-kb(\d{7})-x64-ndp481_',
                    'excel' : 'Windows11.0-KB#f1#-x64-NDP481-KOR.msu'
                }
            ],
            'descriptionInEnglish' : 'Cumulative Update for .NET Framework #dv# for Windows 11_22H2 for x64',
			'group' : 2
        },
        {
            'regex' : 'x64용 Microsoft server operating system version (\w{4})용 .NET Framework (.+) 누적',
            'excel' : '	Q#ki# 10_#1#_x64	#gi#	#ki#	9	W10		#df1#	Cumulative Update for .NET Framework #dv# for Microsoft server operating system version #1# for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'windows10.0-kb(\d{7})-x64-ndp481_',
                    'excel' : 'Windows10.0-#1#-KB#f1#-x64-NDP481-KOR.msu'
                },
                {
                    'regex' : 'windows10.0-kb(\d{7})-x64-ndp48_',
                    'excel' : 'Windows10.0-#1#-KB#f1#-x64-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Cumulative Update for .NET Framework #dv# for Microsoft server operating system version #1# for x64',
			'group' : 2
        },
        {
            'regex' : 'Microsoft server operating system  version (\w{4}) x64에 대한 .NET Framework (.+) 누적',
            'excel' : '	Q#ki# 10_#1#_x64	#gi#	#ki#	9	W10		#df1#	Cumulative Update for .NET Framework #dv# for Microsoft server operating system version #1# for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'windows10.0-kb(\d{7})-x64-ndp48_',
                    'excel' : 'Windows10.0-#1#-KB#f1#-x64-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Cumulative Update for .NET Framework #dv# for Microsoft server operating system version #1# for x64',
			'group' : 2
        },
        {
            'regex' : 'x64용 Windows Server 2008 SP2에 대한 .NET Framework (.+) 보안 전용',
            'excel' : '	Q#ki# 28SP2_x64	#gi#	#ki#	9	W28		#df1#	Security Only Update for .NET Framework #dv# on Windows Server 2008 SP2 for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows6.0-kb(\d{7})',
                    'excel' : 'Windows6.0-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'ndp(\d{2})-kb(\d{7})',
                    'excel' : 'NDP#f1#-KB#f2#-x64-KOR.exe'
                }
            ],
			'descriptionInEnglish' : 'Security Only Update for .NET Framework #dv# on Windows Server 2008 SP2 for x64',
			'group' : 3
        },
        {
            'regex' : 'Windows Server 2008 SP2에 대한 .NET Framework (.+) 보안 전용',
            'excel' : '	Q#ki# 28SP2	#gi#	#ki#	0	W28		#df1#	Security Only Update for .NET Framework #dv# on Windows Server 2008 SP2	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows6.0-kb(\d{7})',
                    'excel' : 'Windows6.0-KB#f1#-x86-KOR.msu'
                },
                {
                    'regex' : 'ndp(\d{2})-kb(\d{7})',
                    'excel' : 'NDP#f1#-KB#f2#-x86-KOR.exe'
                }
            ],
			'descriptionInEnglish' : 'Security Only Update for .NET Framework #dv# on Windows Server 2008 SP2',
			'group' : 3
        },
        {
            'regex' : 'x64 Windows 7용 .NET Framework (.+) 보안 전용',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7,W28R2		#df1#	Security Only Update for .NET Framework #dv# on Windows 7_x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows6.1-kb(\d{7})',
                    'excel' : 'Windows6.1-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'ndp(\d{2})-kb(\d{7})',
                    'excel' : 'NDP#f1#-KB#f2#-x64-KOR.exe'
                }
            ],
			'descriptionInEnglish' : 'Security Only Update for .NET Framework #dv# on Windows 7_x64',
			'group' : 3
        },
        {
            'regex' : 'Windows 7용 .NET Framework (.+) 보안 전용',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7		#df1#	Security Only Update for .NET Framework #dv# on Windows 7	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows6.1-kb(\d{7})',
                    'excel' : 'Windows6.1-KB#f1#-x86-KOR.msu'
                },
                {
                    'regex' : 'ndp(\d{2})-kb(\d{7})',
                    'excel' : 'NDP#f1#-KB#f2#-x86-KOR.exe'
                }
            ],
			'descriptionInEnglish' : 'Security Only Update for .NET Framework #dv# on Windows 7',
			'group' : 3
        },
        {
            'regex' : 'x64 Windows Server 2008 R2용 .NET Framework (.+) 보안 전용',
            'excel' : '	Q#ki# 28R2	#gi#	#ki#	9	W28R2		#df1#	Security Only Update for .NET Framework #dv# on Windows Server 2008 R2_x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows6.1-kb(\d{7})',
                    'excel' : 'Windows6.1-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'ndp(\d{2})-kb(\d{7})',
                    'excel' : 'NDP#f1#-KB#f2#-x64-KOR.exe'
                }
            ],
			'descriptionInEnglish' : 'Security Only Update for .NET Framework #dv# on Windows Server 2008 R2_x64',
			'group' : 3
        },
        {
            'regex' : 'x64 Windows 8.1용 .NET Framework (.+) 보안 전용',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81,W212R2		#df1#	Security Only Update for .NET Framework #dv# on Windows 8.1 for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows8.1-kb(\d{7})-x64_',
                    'excel' : 'Windows8.1-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'windows8.1-kb(\d{7})-x64-ndp48',
                    'excel' : 'Windows8.1-KB#f1#-x64-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Security Only Update for .NET Framework #dv# on Windows 8.1 for x64',
			'group' : 3
        },
        {
            'regex' : 'Windows 8.1용 .NET Framework (.+) 보안 전용',
            'excel' : '	Q#ki# 81	#gi#	#ki#	0	W81		#df1#	Security Only Update for .NET Framework #dv# on Windows 8.1	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows8.1-kb(\d{7})-x86_',
                    'excel' : 'Windows8.1-KB#f1#-x86-KOR.msu'
                },
                {
                    'regex' : 'windows8.1-kb(\d{7})-x86-ndp48',
                    'excel' : 'Windows8.1-KB#f1#-x86-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Security Only Update for .NET Framework #dv# on Windows 8.1',
			'group' : 3
        },
        {
            'regex' : 'x64 Windows Server 2012 R2용 .NET Framework (.+) 보안 전용',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W81,W212R2		#df1#	Security Only Update for .NET Framework #dv# on Windows Server 2012 R2 for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows8.1-kb(\d{7})-x64_',
                    'excel' : 'Windows8.1-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'windows8.1-kb(\d{7})-x64-ndp48',
                    'excel' : 'Windows8.1-KB#f1#-x64-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Security Only Update for .NET Framework #dv# on Windows Server 2012 R2 for x64',
			'group' : 3
        },
        {
            'regex' : 'x64 Windows Server 2012용 .NET Framework (.+) 보안 전용',
            'excel' : '	Q#ki# 212_64	#gi#	#ki#	9	W212		#df1#	Security Only Update for .NET Framework #dv# on Windows Server 2012 for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows8-rt-kb(\d{7})-x64_',
                    'excel' : 'Windows8-RT-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'windows8-rt-kb(\d{7})-x64-ndp48',
                    'excel' : 'Windows8-RT-KB#f1#-x64-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Security Only Update for .NET Framework #dv# on Windows Server 2012 for x64',
			'group' : 3
        },
        {
            'regex' : 'Windows Server 2008 SP2에 대한 .NET Framework (.+) 보안 및',
            'excel' : '	Q#ki# 28SP2	#gi#	#ki#	0	W28		#df1#	Security and Quality Rollup for .NET Framework #dv# on Windows Server 2008 SP2	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows6.0-kb(\d{7})',
                    'excel' : 'Windows6.0-KB#f1#-x86-KOR.msu'
                },
                {
                    'regex' : 'ndp(\d{2})-kb(\d{7})',
                    'excel' : 'NDP#f1#-KB#f2#-x86-KOR.exe'
                }
            ],
			'descriptionInEnglish' : 'Security and Quality Rollup for .NET Framework #dv# on Windows Server 2008 SP2',
			'group' : 4
        },
        {
            'regex' : 'Windows Server 2008 x64용 SP2에서 .NET Framework (.+)을 위한 보안 및',
            'excel' : '	Q#ki# 28SP2_x64	#gi#	#ki#	9	W28		#df1#	Security and Quality Rollup for .NET Framework #dv# on Windows Server 2008 SP2 for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows6.0-kb(\d{7})',
                    'excel' : 'Windows6.0-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'ndp(\d{2})-kb(\d{7})',
                    'excel' : 'NDP#f1#-KB#f2#-x64-KOR.exe'
                }
            ],
			'descriptionInEnglish' : 'Security and Quality Rollup for .NET Framework #dv# on Windows Server 2008 SP2 for x64',
			'group' : 4
        },
        {
            'regex' : 'x64 Windows 7용 .NET Framework (.+) 보안 및',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7		#df1#	Security and Quality Rollup for .NET Framework #dv# on Windows 7_x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows6.1-kb(\d{7})',
                    'excel' : 'Windows6.1-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'ndp(\d{2})-kb(\d{7})',
                    'excel' : 'NDP#f1#-KB#f2#-x64-KOR.exe'
                }
            ],
			'descriptionInEnglish' : 'Security and Quality Rollup for .NET Framework #dv# on Windows 7 for x64',
			'group' : 4
        },
        {
            'regex' : 'Windows 7용 .NET Framework (.+) 보안 및',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7		#df1#	Security and Quality Rollup for .NET Framework #dv# on Windows 7	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows6.1-kb(\d{7})',
                    'excel' : 'Windows6.1-KB#f1#-x86-KOR.msu'
                },
                {
                    'regex' : 'ndp(\d{2})-kb(\d{7})',
                    'excel' : 'NDP#f1#-KB#f2#-x86-KOR.exe'
                }
            ],
			'descriptionInEnglish' : 'Security and Quality Rollup for .NET Framework #dv# on Windows 7',
			'group' : 4
        },
        {
            'regex' : 'x64 Windows Server 2008 R2용 .NET Framework (.+) 보안 및',
            'excel' : '	Q#ki# 28R2	#gi#	#ki#	9	W28R2		#df1#	Security and Quality Rollup for .NET Framework #dv# on Windows Server 2008 R2 for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows6.1-kb(\d{7})',
                    'excel' : 'Windows6.1-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'ndp(\d{2})-kb(\d{7})',
                    'excel' : 'NDP#f1#-KB#f2#-x64-KOR.exe'
                }
            ],
			'descriptionInEnglish' : 'Security and Quality Rollup for .NET Framework #dv# on Windows Server 2008 R2 for x64',
			'group' : 4
        },
        {
            'regex' : 'x64 Windows 8.1용 .NET Framework (.+) 보안 및',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81,W212R2		#df1#	Security and Quality Rollup for .NET Framework #dv# on Windows 8.1_x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows8.1-kb(\d{7})-x64_',
                    'excel' : 'Windows8.1-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'windows8.1-kb(\d{7})-x64-ndp48',
                    'excel' : 'Windows8.1-KB#f1#-x64-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Security and Quality Rollup for .NET Framework #dv# on Windows 8.1 for x64',
			'group' : 4
        },
        {
            'regex' : 'Windows 8.1용 .NET Framework (.+) 보안 및',
            'excel' : '	Q#ki# 81	#gi#	#ki#	0	W81		#df1#	Security and Quality Rollup for .NET Framework #dv# on Windows 8.1	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows8.1-kb(\d{7})-x86_',
                    'excel' : 'Windows8.1-KB#f1#-x86-KOR.msu'
                },
                {
                    'regex' : 'windows8.1-kb(\d{7})-x86-ndp48',
                    'excel' : 'Windows8.1-KB#f1#-x86-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Security and Quality Rollup for .NET Framework #dv# on Windows 8.1',
			'group' : 4
        },
        {
            'regex' : 'x64 Windows Server 2012 R2용 .NET Framework (.+) 보안 및',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W81,W212R2		#df1#	Security and Quality Rollup for .NET Framework #dv# on Windows Server 2012 R2	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows8.1-kb(\d{7})-x64_',
                    'excel' : 'Windows8.1-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'windows8.1-kb(\d{7})-x64-ndp48',
                    'excel' : 'Windows8.1-KB#f1#-x64-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Security and Quality Rollup for .NET Framework #dv# on Windows Server 2012 R2',
			'group' : 4
        },
        {
            'regex' : 'x64 Windows Server 2012용 .NET Framework (.+) 보안 및',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212		#df1#	Security and Quality Rollup for .NET Framework #dv# on Windows Server 2012 for x64	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /q /norestart	!pass!	!pass!	!pass!',
            'fileName' : [
                {
                    'regex' : 'windows8-rt-kb(\d{7})-x64_',
                    'excel' : 'Windows8-RT-KB#f1#-x64-KOR.msu'
                },
                {
                    'regex' : 'windows8-rt-kb(\d{7})-x64-ndp48',
                    'excel' : 'Windows8-RT-KB#f1#-x64-NDP48-KOR.msu'
                }
            ],
			'descriptionInEnglish' : 'Security and Quality Rollup for .NET Framework #dv# on Windows Server 2012 for x64',
			'group' : 4
        },
        {
            'regex' : '.NET Core (.+) Security Update for x86 Client',
            'excel' : '	Q#ki# dotNETCore_Client	#gi#	#ki#	99	W7,W10,212R2		#df1#	.NET Core #dv# Security Update for x86 Client	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'dotnet-sdk-(.+)',
                    'excel' : 'dotnet-sdk-#f1#-win-x86-KOR.exe'
                },
                {
                    'regex' : 'dotnet-runtime-(.+)',
                    'excel' : 'dotnet-runtime-#f1#-win-x86-KOR.exe'
                },
                {
                    'regex' : 'dotnet-hosting-(.+)',
                    'excel' : 'dotnet-hosting-#f1#-win-KOR.exe'
                },
                {
                    'regex' : 'aspnetcore-runtime-(.+)',
                    'excel' : 'aspnetcore-runtime-#f1#-win-x86-KOR.exe'
                },
                {
                    'regex' : 'windowsdesktop-runtime-(.+)',
                    'excel' : 'windowsdesktop-runtime-#f1#-win-x86-KOR.exe'
                }
            ],
			'descriptionInEnglish' : '.NET Core #dv# Security Update for x86 Client',
			'group' : 5
        },
        {
            'regex' : '.NET Core (.+) Security Update for x64 Client',
            'excel' : '	Q#ki# dotNETCore_Client_x64	#gi#	#ki#	99	W7,W10,212R2		#df1#	.NET Core #dv# Security Update for x64 Client	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'dotnet-sdk-(.+)-win-x(\d{2})',
                    'excel' : 'dotnet-sdk-#f1#-win-x#f2#-KOR.exe'
                },
                {
                    'regex' : 'aspnetcore-runtime-(.+)-win-x(\d{2})',
                    'excel' : 'aspnetcore-runtime-#f1#-win-x#f2#-KOR.exe'
                },
                {
                    'regex' : 'dotnet-hosting-(.+)-win',
                    'excel' : 'dotnet-hosting-#f1#-win-KOR.exe'
                },
                {
                    'regex' : 'windowsdesktop-runtime-(.+)-win-x(\d{2})',
                    'excel' : 'windowsdesktop-runtime-#f1#-win-x#f2#-KOR.exe'
                },
                {
                    'regex' : 'dotnet-runtime-(.+)-win-x(\d{2})',
                    'excel' : 'dotnet-runtime-#f1#-win-x#f2#-KOR.exe'
                }
            ],
			'descriptionInEnglish' : '.NET Core #dv# Security Update for x64 Client',
			'group' : 6
        },
        {
            'regex' : '.NET Core (.+) Security Update for x64 Server',
            'excel' : '	Q#ki# dotNETCore_Server_x64	#gi#	#ki#	99	WVT,W28,W7,W28R2,W8,W81,W212,W212R2,W10,W216		#df1#	.NET Core #dv# Security Update for x64 Server	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'dotnet-sdk-(.+)-win-x(\d{2})',
                    'excel' : 'dotnet-sdk-#f1#-win-x#f2#-KOR.exe'
                },
                {
                    'regex' : 'aspnetcore-runtime-(.+)-win-x(\d{2})',
                    'excel' : 'aspnetcore-runtime-#f1#-win-x#f2#-KOR.exe'
                },
                {
                    'regex' : 'dotnet-hosting-(.+)-win',
                    'excel' : 'dotnet-hosting-#f1#-win-KOR.exe'
                },
                {
                    'regex' : 'windowsdesktop-runtime-(.+)-win-x(\d{2})',
                    'excel' : 'windowsdesktop-runtime-#f1#-win-x#f2#-KOR.exe'
                },
                {
                    'regex' : 'dotnet-runtime-(.+)-win-x(\d{2})',
                    'excel' : 'dotnet-runtime-#f1#-win-x#f2#-KOR.exe'
                },
            ],
			'descriptionInEnglish' : '.NET Core #dv# Security Update for x64 Server',
			'group' : 6
        },
        {
            'regex' : '.NET (.+) Security Update for x86 Client',
            'excel' : '	Q#ki# dotNET_Client	#gi#	#ki#	99	W7,W10,212R2		#df1#	.NET #dv# Security Update for x86 Client	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'dotnet-sdk-(.+)-win-x86',
                    'excel' : 'dotnet-sdk-#f1#-win-x86-KOR.exe'
                },
                {
                    'regex' : 'dotnet-hosting-(.+)-win',
                    'excel' : 'dotnet-hosting-#f1#-win-KOR.exe'
                },
                {
                    'regex' : 'windowsdesktop-runtime-(.+)-win',
                    'excel' : 'windowsdesktop-runtime-#f1#-win-x86-KOR.exe'
                },
                {
                    'regex' : 'aspnetcore-runtime-(.+)-win',
                    'excel' : 'aspnetcore-runtime-#f1#-win-x86-KOR.exe'
                },
                {
                    'regex' : 'dotnet-runtime-(.+)-win',
                    'excel' : 'dotnet-runtime-#f1#-win-x86-KOR.exe'
                }
            ],
			'descriptionInEnglish' : '.NET #dv# Security Update for x86 Client',
			'group' : 7
        },
        {
            'regex' : '.NET (.+) Security Update for x64 Client',
            'excel' : '	Q#ki# dotNET_Client_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W81,W212,W212R2,W10,W216		#df1#	.NET #dv# Security Update for x64 Client	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'dotnet-sdk-(.+)-win-x(\d{2})',
                    'excel' : 'dotnet-sdk-#f1#-win-x#f2#-KOR.exe'
                },
                {
                    'regex' : 'dotnet-hosting-(.+)-win',
                    'excel' : 'dotnet-hosting-#f1#-win-KOR.exe'
                },
                {
                    'regex' : 'aspnetcore-runtime-(.+)-win-x(\d{2})',
                    'excel' : 'aspnetcore-runtime-#f1#-win-x#f2#-KOR.exe'
                },
                {
                    'regex' : 'windowsdesktop-runtime-(.+)-win-x(\d{2})',
                    'excel' : 'windowsdesktop-runtime-#f1#-win-x#f2#-KOR.exe'
                },
                {
                    'regex' : 'dotnet-runtime-(.+)-win-x(\d{2})',
                    'excel' : 'dotnet-runtime-#f1#-win-x#f2#-KOR.exe'
                }
            ],
			'descriptionInEnglish' : '.NET #dv# Security Update for x64 Client',
			'group' : 8
        },
        {
            'regex' : '.NET (.+) Security Update for x64 Server',
            'excel' : '	Q#ki# dotNET_Server_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W81,W212,W212R2,W10,W216		#df1#	.NET #dv# Security Update for x64 Server	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	#fn#	1	 /quiet /norestart	!pass!		',
            'fileName' : [
                {
                    'regex' : 'dotnet-sdk-(.+)-win-x(\d{2})',
                    'excel' : 'dotnet-sdk-#f1#-win-x#f2#-KOR.exe'
                },
                {
                    'regex' : 'aspnetcore-runtime-(.+)-win-x(\d{2})',
                    'excel' : 'aspnetcore-runtime-#f1#-win-x#f2#-KOR.exe'
                },
                {
                    'regex' : 'dotnet-runtime-(.+)-win-x(\d{2})',
                    'excel' : 'dotnet-runtime-#f1#-win-x#f2#-KOR.exe'
                },
                {
                    'regex' : 'windowsdesktop-runtime-(.+)-win-x(\d{2})',
                    'excel' : 'windowsdesktop-runtime-#f1#-win-x#f2#-KOR.exe'
                },
                {
                    'regex' : 'dotnet-hosting-(.+)-win',
                    'excel' : 'dotnet-hosting-#f1#-win-KOR.exe'
                }
            ],
			'descriptionInEnglish' : '.NET #dv# Security Update for x64 Server',
			'group' : 8
        }
    ],
    'internet' : [
        {
            'regex' : 'x86 기반 시스템 Windows 7용 Internet Explorer 11',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 7 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE11-Windows6.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Cumulative Security Update for Internet Explorer (Windows 7 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows 7용 Internet Explorer 11',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 7_x64 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE11-Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Cumulative Security Update for Internet Explorer (Windows 7_x64 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템 Windows 8.1용 Internet Explorer 11',
            'excel' : '	Q#ki# 81	#gi#	#ki#	0	W81	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 8.1 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Cumulative Security Update for Internet Explorer (Windows 8.1 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows 8.1용 Internet Explorer 11',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 8.1_x64 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Cumulative Security Update for Internet Explorer (Windows 8.1_x64 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows Server 2008 R2용 Internet Explorer 11',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 2008R2_x64 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE11-Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Cumulative Security Update for Internet Explorer (Windows 2008R2_x64 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows Server 2012용 Internet Explorer 11',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 2012 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE11-Windows6.2-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Cumulative Security Update for Internet Explorer (Windows 2012 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows Server 2012 R2용 Internet Explorer 11',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 2012R2 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Cumulative Security Update for Internet Explorer (Windows 2012R2 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템 Windows Server 2008용 Internet Explorer 9',
            'excel' : '	Q#ki# 28	#gi#	#ki#	0	W28	IE9	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 2008 IE9)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE9-Windows6.0-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Cumulative Security Update for Internet Explorer (Windows 2008 IE9)',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows Server 2008용 Internet Explorer 9',
            'excel' : '	Q#ki# 28_x64	#gi#	#ki#	9	W28	IE9	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 2008_x64 IE9)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE9-Windows6.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Cumulative Security Update for Internet Explorer (Windows 2008_x64 IE9)',
			'group' : 1
        }
    ],
    'azure' : [
        {
            'regex' : 'Cumulative Update for Azure Stack HCI  version 20H2 and  Windows Server 2019',
            'excel' : '	Q#ki# ASHCI	#gi#	#ki#	99	W10		#df1#	Cumulative Update for Azure Stack HCI, version 20H2 and Windows Server 2019 Datacenter- Azure Edition for x64-based Systems	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Cumulative Update for Azure Stack HCI, version 20H2 and Windows Server 2019 Datacenter- Azure Edition for x64-based Systems',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Azure Stack HCI  version 20H2',
            'excel' : '	Q#ki# 10_20H2	#gi#	#ki#	99	W10		#df1#	Servicing Stack Update for Azure Stack HCI, version 20H2 for x64-based Systems	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Servicing Stack Update for Azure Stack HCI, version 20H2 for x64-based Systems',
			'group' : 1
        },
        {
            'regex' : '누적 보안Hotpatch Azure Stack HCI  version (\w{4})용 및 Windows Server (\d{4}) Datacenter: Azure Edition x64',
            'excel' : '	Q#ki# ASHCI	#gi#	#ki#	99	W10		#df1#	Cumulative Update for Azure Stack HCI, version #1# and Windows Server #2# Datacenter- Azure Edition for x64-based Systems	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Cumulative Update for Azure Stack HCI, version #1# and Windows Server #2# Datacenter- Azure Edition for x64-based Systems',
			'group' : 1
        }
    ],
    'exchange' : [
        {
            'regex' : 'Exchange Server 20(\d{2}) (\w{4})',
            'excel' : '	Q#ki# MSES2#1##2#_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10	MS_ES2#1#	#df1#	Microsoft Exchange Server용 보안 업데이트 (Microsoft Exchange Server 20#1# #2#)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Exchange20#1#-#2#-KB#ki#-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for Microsoft Exchange Server 20#1# #2#',
			'group' : 1
        }
    ],
    'powershell' : [
        {
            'regex' : 'PowerShell LTS v(.+)\(x64\)',
            'excel' : '	Q#ki# PS_x64	#gi#	#ki#	9	W10,W11,W212R2		#df1#	PowerShell LTS V.#1#_x64 업데이트	https://github.com/PowerShell/PowerShell/releases/tag/v#1#	#s#	0	Microsoft			1	powershell-#1#-KB#ki#-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for PowerShell LTS V.#1#_x64',
			'group' : 1
        },
        {
            'regex' : 'PowerShell v(.+) \(x64\)',
            'excel' : '	Q#ki# PS_x64	#gi#	#ki#	9	W10,W11,W212R2		#df1#	PowerShell V.#1#_x64 업데이트	https://github.com/PowerShell/PowerShell/releases/tag/v#1#	#s#	0	Microsoft			1	powershell-#1#-KB#ki#-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descriptionInEnglish' : 'Security update for PowerShell V.#1#_x64',
			'group' : 1
        }
    ],
    'etc' : [
        {
            'regex' : 'x64 기반 시스템용 Microsoft server operating system  version (\w{4})에 대한 누적',
            'excel' : '	Q#ki# 10_#1#_x64	#gi#	#ki#	9	W10		#df1#	Microsoft server operating system version #1#_x64 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Microsoft server operating system version #1#_x64 Cumulative update',
			'group' : 1
        },
        {
            'regex' : '누적 업데이트\(Microsoft server operating system version (\w{4}) x64',
            'excel' : '	Q#ki# 10_#1#_x64	#gi#	#ki#	9	W10		#df1#	Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descriptionInEnglish' : 'Cumulative Update for Microsoft server operating system version #1# for x64-based Systems',
			'group' : 1
        }
    ]
}

totalRegexDicByFileName = {
    'sql-server' : [
        {
            'regex' : 'SQL Server 2008 Service Pack (.+) (.+)용',
            'fileName' : [
                {
                    'regex' : 'sqlserver2008-kb(\d{7})-x86',
                    'excel' : '	Q#ki# MSSQL28SP#1##2#	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10	MS_SQL28	#df1#	SQL Server용 보안 업데이트 (Microsoft SQL Server 2008 SP#1# #2# 보안 업데이트)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	SQLServer2008-KB#ki#-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
                    'descriptionInEnglish' : 'Security Update for SQL Server (Microsoft SQL Server 2008 SP#1# #2#)'
                },
                {
                    'regex' : 'sqlserver2008-kb(\d{7})-x64',
                    'excel' : '	Q#ki# MSSQL28SP#1##2#_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216,W219	MS_SQL28	#df1#	SQL Server용 보안 업데이트 (Microsoft SQL Server 2008 SP#1# x64 #2# 보안 업데이트)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	SQLServer2008-KB#ki#-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
                    'descriptionInEnglish' : 'Security Update for SQL Server (Microsoft SQL Server 2008 x64 SP#1# #2#)'
                }
            ],
			'group' : 1
        },
        {
            'regex' : 'SQL Server 2008 R2 Service Pack (.+) (.+)용',
            'fileName' : [
                {
                    'regex' : 'sqlserver2008r2-kb(\d{7})-x86',
                    'excel' : '	Q#ki# MSSQL28R2SP#1##2#	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10	MS_SQL28R2	#df1#	SQL Server용 보안 업데이트 (Microsoft SQL Server 2008 R2 SP#1# #2# 보안 업데이트)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	SQLServer2008R2-KB#ki#-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
                    'descriptionInEnglish' : 'Security Update for SQL Server (Microsoft SQL Server 2008 R2 SP#1# #2#)'
                },
                {
                    'regex' : 'sqlserver2008r2-kb(\d{7})-x64',
                    'excel' : '	Q#ki# MSSQL28R2SP#1##2#_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216,W219	MS_SQL28R2	#df1#	SQL Server용 보안 업데이트 (Microsoft SQL Server 2008 R2 SP#1# x64 #2 보안 업데이트)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	SQLServer2008R2-KB#ki#-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
                    'descriptionInEnglish' : 'Security Update for SQL Server (Microsoft SQL Server 2008 R2 x64 SP#1# #2#)'
                }
            ],
			'group' : 1
        },
        {
            'regex' : 'SQL Server 2012 Service Pack (.+) (.+)용',
            'fileName' : [
                {
                    'regex' : 'sqlserver2012-kb(\d{7})-x86',
                    'excel' : '	Q#ki# MSSQL212SP#1##2#	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10	MS_SQL212	#df1#	SQL Server용 보안 업데이트 (Microsoft SQL Server 2012 SP#1# #2# 보안 업데이트)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	SQLServer2012-KB#ki#-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
                    'descriptionInEnglish' : 'Security Update for SQL Server (Microsoft SQL Server 2012 SP#1# #2#)'
                },
                {
                    'regex' : 'sqlserver2012-kb(\d{7})-x64',
                    'excel' : '	Q#ki# MSSQL212SP#1##2#_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216,W219	MS_SQL212	#df1#	SQL Server용 보안 업데이트 (Microsoft SQL Server 2012 SP#1# x64 #2# 보안 업데이트)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	SQLServer2012-KB#ki#-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
                    'descriptionInEnglish' : 'Security Update for SQL Server (Microsoft SQL Server 2012 x64 SP#1# #2#)'
                }
            ],
			'group' : 1
        },
        {
            'regex' : 'SQL Server 2014 Service Pack (.+) (.+)용',
            'fileName' : [
                {
                    'regex' : 'sqlserver2014-kb(\d{7})-x86',
                    'excel' : '	Q#ki# MSSQL214SP#1##2#	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10	MS_SQL214	#df1#	SQL Server용 보안 업데이트 (Microsoft SQL Server 2014 SP#1# #2# 보안 업데이트)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	SQLServer2014-KB#ki#-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
                    'descriptionInEnglish' : 'Security Update for SQL Server (Microsoft SQL Server 2014 SP#1# #2#)'
                },
                {
                    'regex' : 'sqlserver2014-kb(\d{7})-x64',
                    'excel' : '	Q#ki# MSSQL214SP#1##2#_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216,W219	MS_SQL214	#df1#	SQL Server용 보안 업데이트 (Microsoft SQL Server 2014 SP#1# x64 #2# 보안 업데이트)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	SQLServer2014-KB#ki#-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
                    'descriptionInEnglish' : 'Security Update for SQL Server (Microsoft SQL Server 2014 SP#1# x64 #2#)'
                }
            ],
			'group' : 1
        },
        {
            'regex' : 'SQL Server 2016 Service Pack (.+) (.+)용',
            'fileName' : [
                {
                    'regex' : 'sqlserver2016-kb(\d{7})-x64',
                    'excel' : '	Q#ki# MSSQL216SP#1##2#_x64	#gi#	#ki#	9	W8,W212,W81,W212R2,W216	MS_SQL216	#df1#	SQL Server용 보안 업데이트 (Microsoft SQL Server 2016 SP#1# x64 #2# 보안 업데이트)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	SQLServer2016-KB#ki#-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
                    'descriptionInEnglish' : 'Security Update for SQL Server (Microsoft SQL Server 2016 SP#1# x64 #2#)'
                }
            ],
			'group' : 1
        },
        {
            'regex' : 'SQL Server 2017 RTM (.+)용',
            'fileName' : [
                {
                    'regex' : 'sqlserver2017-kb(\d{7})-x64',
                    'excel' : '	Q#ki# MSSQL217RTM#1#_x64	#gi#	#ki#	9	WXP,W23,WVT,W28,W7,W8,W81,W10,W212	MS_SQL217	#df1#	SQL Server용 보안 업데이트 (Microsoft SQL Server 2017 RTM x64 #1# 보안 업데이트)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	SQLServer2017-KB#ki#-x64-KOR.exe	1	 /quiet	!pass!	!pass!	!pass!',
                    'descriptionInEnglish' : 'Security Update for SQL Server (Microsoft SQL Server 2017 RTM x64 #1#)'
                }
            ],
			'group' : 1
        },
        {
            'regex' : 'SQL Server 2019 RTM (.+)용',
            'fileName' : [
                {
                    'regex' : 'sqlserver2019-kb(\d{7})-x64',
                    'excel' : '	Q#ki# MSSQL219RTM#1#_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216,W219	MS_SQL219	#df1#	SQL Server용 보안 업데이트 (Microsoft SQL Server 2019 RTM x64 #1# 보안 업데이트)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	SQLServer2019-KB#ki#-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
                    'descriptionInEnglish' : 'Security Update for SQL Server (Microsoft SQL Server 2019 RTM x64 #1#)'
                }
            ],
			'group' : 1
        },
        {
            'regex' : 'SQL Server 2022 RTM (.+)용',
            'fileName' : [
                {
                    'regex' : 'sqlserver2022-kb(\d{7})-x64',
                    'excel' : '	Q#ki# MSSQL222RTM#1#_x64	#gi#	#ki#	9	W10,W216,W219,W11,W2022	MS_SQL222	#df1#	SQL Server용 보안 업데이트 (Microsoft SQL Server 2022 RTM x64 #1# 보안 업데이트)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	SQLServer2022-KB#ki#-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
                    'descriptionInEnglish' : 'Security Update for SQL Server (Microsoft SQL Server 2022 RTM x64 #1#)'
                }
            ],
			'group' : 1
        }
    ],
    'azure-file-sync-agent' : [
        {
            'regex' : 'Azure File Sync Agent',
            'fileName' : [
                {
                    'regex' : 'storagesyncagent_ws2012r2_',
                    'excel' : '	Q#ki# 212R2	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Update Rollup for Azure File Sync Agent (Windows Server 2012R2)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	StorageSyncAgent-WS2012R2-KB#ki#-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup for Azure File Sync Agent (Windows Server 2012R2)'
                },
                {
                    'regex' : 'storagesyncagent_ws2016_',
                    'excel' : '	Q#ki# 216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Update Rollup for Azure File Sync Agent (Windows Server 2016)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	StorageSyncAgent-WS2016-KB#ki#-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup for Azure File Sync Agent (Windows Server 2016)'
                },
                {
                    'regex' : 'storagesyncagent_ws2019_',
                    'excel' : '	Q#ki# 219	#gi#	#ki#	9	W219		#df1#	Update Rollup for Azure File Sync Agent (Windows Server 2019)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	StorageSyncAgent-WS2019-KB#ki#-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup for Azure File Sync Agent (Windows Server 2019)'
                },
                {
                    'regex' : 'storagesyncagent_ws2022_',
                    'excel' : '	Q#ki# 222	#gi#	#ki#	9	W2022		#df1#	Update Rollup for Azure File Sync Agent (Windows Server 2022)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	StorageSyncAgent-WS2022-KB#ki#-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup for Azure File Sync Agent (Windows Server 2022)'
                }
            ],
			'group' : 1
        }
    ],
    'microsoft-system-center' : [
        {
            'regex' : 'Microsoft System Center 2022 용',
            'fileName' : [
                {
                    'regex' : 'kb(\d{7})_vmmserver_',
                    'excel' : '	Q#ki# MSSC222	#gi#	#ki#	9	W216,W10,W212R2,W219		#df1#	Microsoft System Center 2022 용 업데이트 롤업 1 - Virtual Machine Manager	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	kb#ki#_vmmserver-x64-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for Microsoft System Center 2022 - Virtual Machine Manager'
                },
                {
                    'regex' : 'kb(\d{7})_adminconsole_',
                    'excel' : '	Q#ki# MSSC222	#gi#	#ki#	0	W216,W219		#df1#	Microsoft System Center 2022 용 업데이트 롤업 1 - Virtual Machine Manager	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	kb#ki#_AdminConsole-x84-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for Microsoft System Center 2022 - Virtual Machine Manager'
                }
            ],
            'group' : 1
        },
        {
            'regex' : 'Microsoft System Center 2022 - Operations Manager',
            'fileName' : [
                {
                    'regex' : 'kb(\d{7})-amd64-gateway_',
                    'excel' : '	Q#ki# MSSC222	#gi#	#ki#	9	W216,W219		#df1#	Microsoft System Center 2022 - Operations Manager Geteway 업데이트 롤업 1	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	KB#ki#-Gateway-x64-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for Microsoft System Center 2022 - Operations Manager Geteway'
                },
                {
                    'regex' : 'kb(\d{7})-amd64-agent_',
                    'excel' : '	Q#ki# MSSC222_x64	#gi#	#ki#	9	W216,W10,W212R2,W212,W219		#df1#	Microsoft System Center 2022_x64 - Operations Manager Agent 업데이트 롤업 1	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	KB#ki#-Agent-x64-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for Microsoft System Center 2022_x64 - Operations Manager Agent'
                },
                {
                    'regex' : 'kb(\d{7})-amd64-console_',
                    'excel' : '	Q#ki# MSSC222	#gi#	#ki#	9	W216,W10,W212R2,W219		#df1#	Microsoft System Center 2022 - Operations Manager Console 업데이트 롤업 1	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	KB#ki#-Console-x64-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for Microsoft System Center 2022 - Operations Manager Console'
                },
                {
                    'regex' : 'kb(\d{7})-amd64-reporting_',
                    'excel' : '	Q#ki# MSSC222	#gi#	#ki#	9	W216,W219		#df1#	Microsoft System Center 2022 - Operations Manager Reportiong 업데이트 롤업 1	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	KB#ki#-Reporting-x64-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for Microsoft System Center 2022 - Operations Manager Reportiong'
                },
                {
                    'regex' : 'kb(\d{7})-amd64-server_',
                    'excel' : '	Q#ki# MSSC222_x64	#gi#	#ki#	9	W216,W10,W212R2,W219		#df1#	Microsoft System Center 2022_x64 - Operations Manager Server 업데이트 롤업 1	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	KB#ki#-Server-x64-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for Microsoft System Center 2022_x64 - Operations Manager Server'
                },
                {
                    'regex' : 'kb(\d{7})-amd64-webconsole_',
                    'excel' : '	Q#ki# MSSC222	#gi#	#ki#	9	W216,W10,W212R2,W219		#df1#	Microsoft System Center 2022 - Operations Manager WebConsole 업데이트 롤업 1	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	KB#ki#-WebConsole-x64-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for Microsoft System Center 2022 - Operations Manager WebConsole'
                },
                {
                    'regex' : 'kb(\d{7})-amd64-acs_',
                    'excel' : '	Q#ki# MSSC222	#gi#	#ki#	9	W216,W219		#df1#	Microsoft System Center 2022 - Operations Manager ACS 업데이트 롤업 1	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	KB#ki#-ACS-x64-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for Microsoft System Center 2022 - Operations Manager ACS'
                }
            ],
            'group' : 2
        },
        {
            'regex' : 'Update Rollup 1 for Microsoft System Center 2022',
            'fileName' : [
                {
                    'regex' : 'kb(\d{7})_microsoft.systemcenter.orchestrator.runbookserver_x64',
                    'excel' : '	Q#ki# MSSC222	#gi#	#ki#	99	W216		#df1#	Update Rollup 1 for System Center 2022_x64 - Orchestrator Runbook Server	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	KB#ki#-runbookserver-x64-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for System Center 2022_x64 - Orchestrator Runbook Server'
                },
                {
                    'regex' : 'kb(\d{7})_microsoft.systemcenter.orchestrator.runbookdesigner_x64',
                    'excel' : '	Q#ki# MSSC222	#gi#	#ki#	99	W216		#df1#	Update Rollup 1 for System Center 2022_x64 - Orchestrator Runbook Designer	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	KB#ki#-runbookdesigner-x64-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for System Center 2022_x64 - Orchestrator Runbook Designer'
                },
                {
                    'regex' : 'kb(\d{7})_microsoft.systemcenter.orchestrator.webconsole_x64',
                    'excel' : '	Q#ki# MSSC222	#gi#	#ki#	99	W216		#df1#	Update Rollup 1 for System Center 2022_x64 - Orchestrator Web Console	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	KB#ki#-webconsole-x64-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for System Center 2022_x64 - Orchestrator Web Console'
                },
                {
                    'regex' : 'kb(\d{7})_microsoft.systemcenter.orchestrator.managementserver_x64',
                    'excel' : '	Q#ki# MSSC222	#gi#	#ki#	99	W216		#df1#	Update Rollup 1 for System Center 2022_x64 - Orchestrator Management Server	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	KB#ki#-managementserver-x64-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for System Center 2022_x64 - Orchestrator Management Server'
                },
                {
                    'regex' : 'kb(\d{7})_microsoft.systemcenter.orchestrator.webapi_x64',
                    'excel' : '	Q#ki# MSSC222	#gi#	#ki#	99	W216		#df1#	Update Rollup 1 for System Center 2022_x64 - Orchestrator Web API	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	KB#ki#-webapi-x64-KOR.msp	1	 /quiet /norestart	!pass!		',
                    'descriptionInEnglish' : 'Update Rollup 1 for System Center 2022_x64 - Orchestrator Web API'
                }
            ],
            'group' : 3
        }
    ]
}

totalRowDic = {
    'windows-cumulative' : {},
    'windows-security' : {},
    'windows-etc' : {},
    'office' : {},
    'internet' : {},
    'dotnet' : {},
    'azure' : {},
    'azure-file-sync-agent' : {},
    'exchange' : {},
    'powershell' : {},
    'sql-server' : {},
    'microsoft-system-center' : {},
    'etc' : {}
}