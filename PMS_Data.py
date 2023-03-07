patchExclusionList = ['ARM', 'arm', 'Embedded', '팜', '팝', 'Itanium', 'POS']
officeList = ['Office', 'Word', 'Excel', 'Outlook', 'PowerPoint', 'Visio', 'Publisher', 'SharePoint']

"""
#ki# : KBID
#gi# : GUID
#s# : Severity
"""
totalRegexDic = {
    'windows-cumulative' : [
        {
            'regex' : 'x86 기반 시스템용 Windows 10 Version (\w{4})에 대한 누적',
            'excel' : '	Q#ki# 10_#1#	#gi#	#ki#	0	W10		#df1#	Windows 10 #1# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descr_enu' : 'Windows 10 #1# Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 10 Version (\w{4})에 대한 누적',
            'excel' : '	Q#ki# 10_#1#_x64	#gi#	#ki#	9	W10		#df1#	Windows 10_x64 #1# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descr_enu' : 'Windows 10_x64 #1# Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11 Version (\w{4})에 대한 누적',
            'excel' : '	Q#ki# 11_#1#_x64	#gi#	#ki#	9	W11		#df1#	Windows 11 #1# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descr_enu' : 'Windows 11_x64 #1# Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11에 대한 누적',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	Windows 11 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descr_enu' : 'Windows 11_x64 Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 10 Version (\w{4}) for x86',
            'excel' : '	Q#ki# 10_#1#	#gi#	#ki#	0	W10		#df1#	Windows 10 #1# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descr_enu' : 'Windows 10 #1# Dynamic Cumulative update',
            'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 10 Version (\w{4}) for x64',
            'excel' : '	Q#ki# 10_#1#_x64	#gi#	#ki#	9	W10		#df1#	Windows 10_x64 #1# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 10_x64 22H2 Dynamic Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 11 Version (\w{4}) for x64',
            'excel' : '	Q#ki# 11_#1#x64	#gi#	#ki#	9	W11		#df1#	Windows 11_x64 #1# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 11_x64 #1# Dynamic Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 11 for x64',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	Windows 11_x64 Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 11 Dynamic Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2016에 대한 누적',
            'excel' : '	Q#ki# 216	#gi#	#ki#	9	W216		#df1#	Windows 2016_x64 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-1607-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 2016_x64 Cumulative update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2019에 대한 누적',
            'excel' : '	Q#ki# 219	#gi#	#ki#	9	W219		#df1#	Windows 2019_x64 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-1809-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 2019_x64 Cumulative update',
			'group' : 1
        }
    ],
    'windows-security' : [
        {
            'regex' : 'x86 기반 시스템용 Windows Server 2008에 대한 보안 전용',
            'excel' : '	Q#ki# 28	#gi#	#ki#	0	W28		#df1#	Windows 2008 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.0-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 2008 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x86 기반 시스템용 Windows Server 2008에 대한 보안 월별',
            'excel' : '	Q#ki# 28	#gi#	#ki#	0	W28		#df1#	Windows 2008 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.0-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 2008 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 7에 대한 보안 전용',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7		#df1#	Windows 7 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 7 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x86 기반 시스템용 Windows 7에 대한 보안 월별',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7		#df1#	Windows 7 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 7 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 8.1에 대한 보안 전용',
            'excel' : '	Q#ki# 81	#gi#	#ki#	0	W81		#df1#	Windows 8.1 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 8.1 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x86 기반 시스템용 Windows 8.1에 대한 보안 월별',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	Windows 8.1_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 8.1 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008에 대한 보안 전용',
            'excel' : '	Q#ki# 28_x64	#gi#	#ki#	9	W28		#df1#	Windows 2008_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 2008_x64 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x64 기반 시스템용 Windows Server 2008에 대한 보안 월별',
            'excel' : '	Q#ki# 28_x64	#gi#	#ki#	9	W28		#df1#	Windows 2008_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 2008_x64 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 7에 대한 보안 전용',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7		#df1#	Windows 7_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 7_x64 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x64 기반 시스템용 Windows 7에 대한 보안 월별',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7		#df1#	Windows 7_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 7_x64 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 8.1에 대한 보안 전용',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	Windows 8.1_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 8.1_x64 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x64 기반 시스템용 Windows 8.1에 대한 보안 월별',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	Windows 8.1_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 8.1_x64 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008 R2에 대한 보안 전용',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2		#df1#	Windows 2008R2_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 2008R2_x64 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x64 기반 시스템용 Windows Server 2008 R2에 대한 보안 월별',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2		#df1#	Windows 2008R2_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 2008R2_x64 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012에 대한 보안 전용',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212		#df1#	Windows 2012 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8-RT-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 2012 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x64 기반 시스템용 Windows Server 2012에 대한 보안 월별',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212		#df1#	Windows 2012 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8-RT-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 2012 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012 R2에 대한 보안 전용',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2		#df1#	Windows 2012R2 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 2012R2 Security Only Update',
			'group' : 1
        },
        {
            'regex' : '#df0#월  x64 기반 시스템용 Windows Server 2012 R2에 대한 보안 월별',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2		#df1#	Windows 2012R2 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Windows 2012R2 Monthly Rollup Update',
			'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 10 Version 22H2 보안',
            'excel' : '	Q#ki# 10_22H2	#gi#	#ki#	0	W10		#df1#	Windows 10 22H2 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-22H2-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descr_enu' : 'Security update for Windows 10 22H2',
            'group' : 2
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 10 Version 22H2 보안',
            'excel' : '	Q#ki# 10_22H2_x64	#gi#	#ki#	9	W10		#df1#	Windows 10_x64 22H2 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-22H2-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descr_enu' : 'Security update for Windows 10_x64 22H2',
            'group' : 2
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11 22H2 보안',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	Windows 11 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'descr_enu' : 'Security update for Windows 11',
            'group' : 2
        }
    ],
    "office" : [
        {
            'regex' : 'Microsoft Office 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSO213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Office 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	oart2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Office 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Office 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSO213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Office 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	oart2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Office 2013_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Office 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSO216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Office 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	oart2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Office 2016',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Office 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSO216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Office 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	oart2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Office 2016_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Word 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSW213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Word 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	word2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Word 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Word 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSW213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Word 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	word2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Word 2013_64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Word 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSW216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Word 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	word2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Word 2016',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Word 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSW216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Word 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	word2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Word 2016_64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Excel 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MOE213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Excel 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	excel2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Excel 2013 ',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Excel 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MOE213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Excel 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	excel2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Excel 2013_x64 ',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Excel 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MOE216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Excel 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	excel2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Excel 2016 ',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Excel 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MOE216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Excel 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	excel2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Excel 2016_x64 ',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Outlook 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSOO213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Outlook 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	outlook2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Outlook 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Outlook 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSOO213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Outlook 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	outlook2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Outlook 2013_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Outlook 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSOO216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Outlook 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	outlook2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Outlook 2016',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Outlook 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSOO216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Outlook 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	outlook2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Outlook 2016_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft PowerPoint 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSPP213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft PowerPoint 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	powerpoint2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft PowerPoint 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft PowerPoint 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSPP213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft PowerPoint 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	powerpoint2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft PowerPoint 2013_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft PowerPoint 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSPP216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft PowerPoint 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	powerpoint2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft PowerPoint 2016',
			'group' : 1
        },
        {
            'regex' : 'Microsoft PowerPoint 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSPP216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft PowerPoint 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	powerpoint2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft PowerPoint 2016_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Visio 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MV213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Visio 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	visio2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Visio 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Visio 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MV213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Visio 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	visio2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Visio 2013_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Visio 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MV216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Visio 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	visio2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Visio 2016',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Visio 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MV216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Visio 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	visio2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Visio 2016_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Publisher 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MP213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Publisher 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	publisher2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Publisher 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Publisher 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MP213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Publisher 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	publisher2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Publisher 2013_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Publisher 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MP216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Publisher 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	publisher2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Publisher 2016',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Publisher 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MP216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	Microsoft Publisher 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	publisher2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Publisher 2016_x64',
			'group' : 1
        },
        {
            'regex' : 'Microsoft SharePoint Foundation 2013용 보안',
            'excel' : '	Q#ki# MSSPF213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W81,W212,W212R2,W10,W216		#df1#	Microsoft SharePoint Foundation 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	sts2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft SharePoint Foundation 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft SharePoint Enterprise Server 2013용 보안',
            'excel' : '	Q#ki# MSSPS213	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W81,W212,W212R2,W10,W216		#df1#	Microsoft SharePoint Enterprise Server 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	coreserverloc2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft SharePoint Enterprise Server 2013',
			'group' : 1
        },
        {
            'regex' : 'Microsoft Office Web Apps Server 2013용 보안',
            'excel' : '	Q#ki# MSOWAS213	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W81,W212,W212R2,W10,W216		#df1#	Microsoft Office Web Apps Server 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	wacserver2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Office Web Apps Server 2013',
			'group' : 1
        }
    ],
    'internet' : [
        {
            'regex' : 'x86 기반 시스템 Windows 7용 Internet Explorer 11',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 7 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE11-Windows6.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Cumulative Security Update for Internet Explorer (Windows 7 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows 7용 Internet Explorer 11',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 7_x64 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE11-Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Cumulative Security Update for Internet Explorer (Windows 7_x64 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템 Windows 8.1용 Internet Explorer 11',
            'excel' : '	Q#ki# 81	#gi#	#ki#	0	W81	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 8.1 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Cumulative Security Update for Internet Explorer (Windows 8.1 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows 8.1용 Internet Explorer 11',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 8.1_x64 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Cumulative Security Update for Internet Explorer (Windows 8.1_x64 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows Server 2008 R2용 Internet Explorer 11',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 2008R2_x64 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE11-Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Cumulative Security Update for Internet Explorer (Windows 2008R2_x64 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows Server 2012용 Internet Explorer 11',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 2012 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE11-Windows6.2-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Cumulative Security Update for Internet Explorer (Windows 2012 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows Server 2012 R2용 Internet Explorer 11',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2	IE11	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 2012R2 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Cumulative Security Update for Internet Explorer (Windows 2012R2 IE11)',
			'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템 Windows Server 2008용 Internet Explorer 9',
            'excel' : '	Q#ki# 28	#gi#	#ki#	0	W28	IE9	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 2008 IE9)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE9-Windows6.0-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Cumulative Security Update for Internet Explorer (Windows 2008 IE9)',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows Server 2008용 Internet Explorer 9',
            'excel' : '	Q#ki# 28_x64	#gi#	#ki#	9	W28	IE9	#df1#	Internet Explorer용 누적 보안 업데이트 (Windows 2008_x64 IE9)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE9-Windows6.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Cumulative Security Update for Internet Explorer (Windows 2008_x64 IE9)',
			'group' : 1
        }
    ],
    'azure' : [
        {
            'regex' : 'Cumulative Update for Azure Stack HCI  version 20H2 and  Windows Server 2019',
            'excel' : '	Q#ki# ASHCI	#gi#	#ki#	99	W10		#df1#	Cumulative Update for Azure Stack HCI, version 20H2 and Windows Server 2019 Datacenter- Azure Edition for x64-based Systems	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Cumulative Update for Azure Stack HCI, version 20H2 and Windows Server 2019 Datacenter- Azure Edition for x64-based Systems',
			'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Azure Stack HCI  version 20H2',
            'excel' : '	Q#ki# 10_20H2	#gi#	#ki#	99	W10		#df1#	Servicing Stack Update for Azure Stack HCI, version 20H2 for x64-based Systems	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
			'descr_enu' : 'Servicing Stack Update for Azure Stack HCI, version 20H2 for x64-based Systems',
			'group' : 1
        }
    ],
    'exchange' : [
        {
            'regex' : 'Exchange Server 20(\d{2}) (\w{4})',
            'excel' : '	Q#ki# MSES2#1##2#_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10	MS_ES2#1#	#df1#	Microsoft Exchange Server용 보안 업데이트 (Microsoft Exchange Server 20#1# #2#)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft	MS16-108, CVE-2016-0138, CVE-2016-3378, CVE-2016-3379	Microsoft Exchange 정보 유출 취약성 - Microsoft Exchange Server가 전자 메일 메시지를 구문 분석하는 방식에 정보 유출 취약성이 존재합니다. 이 취약성으로 인해 공격자는 Microsoft Outlook 응용 프로그램에 포함된 기밀 사용자 정보를 검색할 수 있습니다.\n공격자는 취약성을 악용하기 위해 "다른 사람 이름으로 보내기" 권한을 사용하여 특수 제작된 메시지를 사용자에게 보낼 수 있습니다.\n이 보안 업데이트는 Microsoft Exchange가 일부 비구조적 파일 형식을 구문 분석하는 방식을 수정하여 취약성을 해결합니다.\n\nMicrosoft Exchange 공개 리디렉션 취약성 - 스푸핑을 유발할 수 있는 공개 리디렉션 취약성이 Microsoft Exchange에 존재합니다. 이 취약성을 악용하기 위해 공격자는 특수 제작된 URL이 있는 링크를 보내 사용자가 링크를 클릭하도록 유도할 수 있습니다. 인증된 Exchange 사용자가 링크를 클릭하면 인증된 사용자의 브라우저 세션이 적법한 웹 사이트를 가장하도록 설계된 악성 사이트로 리디렉션될 수 있습니다. 이 경우 공격자는 사용자를 속여 잠재적으로 사용자의 자격 증명과 같은 중요 정보를 획득할 수 있습니다.\n이 업데이트는 Exchange가 공개 리디렉션 요청을 처리하는 방식을 수정하여 취약성을 해결합니다.\n\nMicrosoft Exchange 권한 상승 취약성 - Microsoft Outlook이 모임 초대 요청을 처리하는 방식에 권한 상승 취약성이 존재합니다. 이 취약성을 악용하기 위해 공격자는 악성 XSS(교차 사이트 스크립팅) 기능이 있는 특수 제작된 Outlook 모임 초대 요청을 사용자에게 보낼 수 있습니다.\n이 업데이트는 Outlook이 모임 초대 요청을 처리하는 방식을 수정하여 취약성을 해결합니다.	1	Exchange20#1#-#2#-#ki#-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for Microsoft Exchange Server 20#1# #2#',
			'group' : 1
        }
    ],
    'powershell' : [
        {
            'regex' : 'PowerShell LTS v(.+)\(x64\)',
            'excel' : '	Q#ki# PS_x64	#gi#	#ki#	9	W10,W11,W212R2		#df1#	PowerShell LTS V.#1#_x64 업데이트	https://github.com/PowerShell/PowerShell/releases/tag/v#1#	#s#	0	Microsoft			1	powershell-#1#-KB#ki#-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for PowerShell LTS V.#1#_x64',
			'group' : 1
        },
        {
            'regex' : 'PowerShell v(.+) \(x64\)',
            'excel' : '	Q#ki# PS_x64	#gi#	#ki#	9	W10,W11,W212R2		#df1#	PowerShell V.#1#_x64 업데이트	https://github.com/PowerShell/PowerShell/releases/tag/v#1#	#s#	0	Microsoft			1	powershell-#1#-KB#ki#-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
			'descr_enu' : 'Security update for PowerShell V.#1#_x64',
			'group' : 1
        }
    ]
}

totalRowDic = {
    'windows-cumulative' : {},
    'windows-security' : {},
    'office' : {},
    'internet' : {},
    'azure' : {},
    'exchange' : {},
    'powershell' : {}
}