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
            'excel' : '	Q#ki# 10_#1#	#gi#	#ki#	0	W10		#df1#	#df2#, Windows 10 #1# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 10 Version (\w{4})에 대한 누적',
            'excel' : '	Q#ki# 10_#1#_x64	#gi#	#ki#	9	W10		#df1#	#df2#, Windows 10_x64 #1# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11 Version (\w{4})에 대한 누적',
            'excel' : '	Q#ki# 11_#1#_x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11 #1# 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11에 대한 누적',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 10 Version (\w{4}) for x86',
            'excel' : '	Q#ki# 10_#1#	#gi#	#ki#	0	W10		#df1#	#df2#, Windows 10 #1# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 10 Version (\w{4}) for x64',
            'excel' : '	Q#ki# 10_#1#_x64	#gi#	#ki#	9	W10		#df1#	#df2#, Windows 10_x64 #1# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 11 Version (\w{4}) for x64',
            'excel' : '	Q#ki# 11_#1#x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11_x64 #1# Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-#1#-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'Dynamic Cumulative Update for Windows 11 for x64',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11_x64 Dynamic Cumulative 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2016에 대한 누적',
            'excel' : '	Q#ki# 216	#gi#	#ki#	9	W216		#df1#	#df2#, Windows 2016_x64 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-1607-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2019에 대한 누적',
            'excel' : '	Q#ki# 219	#gi#	#ki#	9	W219		#df1#	#df2#, Windows 2019_x64 누적 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-1809-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        }
    ],
    'windows-security' : [
        {
            'regex' : 'x86 기반 시스템용 Windows Server 2008에 대한 보안 전용',
            'excel' : '	Q#ki# 28	#gi#	#ki#	0	W28		#df1#	#df2#, Windows 2008 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.0-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows Server 2008에 대한 보안 월별',
            'excel' : '	Q#ki# 28	#gi#	#ki#	0	W28		#df1#	#df2#, Windows 2008 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.0-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 7에 대한 보안 전용',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7		#df1#	#df2#, Windows 7 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 7에 대한 보안 월별',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7		#df1#	#df2#, Windows 7 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 8.1에 대한 보안 전용',
            'excel' : '	Q#ki# 81	#gi#	#ki#	0	W81		#df1#	#df2#, Windows 8.1 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 8.1에 대한 보안 월별',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	#df2#, Windows 8.1_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008에 대한 보안 전용',
            'excel' : '	Q#ki# 28_x64	#gi#	#ki#	9	W28		#df1#	#df2#, Windows 2008_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008에 대한 보안 월별',
            'excel' : '	Q#ki# 28_x64	#gi#	#ki#	9	W28		#df1#	#df2#, Windows 2008_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 7에 대한 보안 전용',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7		#df1#	#df2#, Windows 7_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 7에 대한 보안 월별',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7		#df1#	#df2#, Windows 7_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 8.1에 대한 보안 전용',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	#df2#, Windows 8.1_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 8.1에 대한 보안 월별',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81		#df1#	#df2#, Windows 8.1_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008 R2에 대한 보안 전용',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2		#df1#	#df2#, Windows 2008R2_x64 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2008 R2에 대한 보안 월별',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2		#df1#	#df2#, Windows 2008R2_x64 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012에 대한 보안 전용',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212		#df1#	#df2#, Windows 2012 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8-RT-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012에 대한 보안 월별',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212		#df1#	#df2#, Windows 2012 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8-RT-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012 R2에 대한 보안 전용',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2		#df1#	#df2#, Windows 2012R2 보안 업데이트 - 보안 전용	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템용 Windows Server 2012 R2에 대한 보안 월별',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2		#df1#	#df2#, Windows 2012R2 보안 업데이트 - 월별 롤업	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템용 Windows 10 Version 22H2 보안',
            'excel' : '	Q#ki# 10_22H2	#gi#	#ki#	0	W10		#df1#	#df2#, Windows 10 22H2 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-22H2-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 2
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 10 Version 22H2 보안',
            'excel' : '	Q#ki# 10_22H2_x64	#gi#	#ki#	9	W10		#df1#	#df2#, Windows 10_x64 22H2 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows10.0-22H2-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 2
        },
        {
            'regex' : 'x64 기반 시스템용 Windows 11 22H2 보안',
            'excel' : '	Q#ki# 11_x64	#gi#	#ki#	9	W11		#df1#	#df2#, Windows 11 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows11.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 2
        }
    ],
    "office" : [
        {
            'regex' : 'Microsoft Office 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSO213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Office 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	oart2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Office 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSO213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Office 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	oart2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Office 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSO216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Office 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	oart2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Office 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSO216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Office 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	oart2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Word 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSW213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Word 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	word2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Word 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSW213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Word 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	word2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Word 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSW216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Word 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	word2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Word 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSW216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Word 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	word2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Excel 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MOE213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Excel 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	excel2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Excel 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MOE213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Excel 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	excel2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Excel 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MOE216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Excel 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	excel2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Excel 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MOE216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Excel 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	excel2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Outlook 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSOO213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Outlook 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	outlook2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Outlook 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSOO213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Outlook 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	outlook2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Outlook 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSOO216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Outlook 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	outlook2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Outlook 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSOO216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Outlook 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	outlook2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft PowerPoint 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSPP213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft PowerPoint 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	powerpoint2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft PowerPoint 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSPP213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft PowerPoint 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	powerpoint2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft PowerPoint 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MSPP216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft PowerPoint 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	powerpoint2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft PowerPoint 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MSPP216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft PowerPoint 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	powerpoint2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Visio 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MV213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Visio 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	visio2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Visio 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MV213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Visio 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	visio2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Visio 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MV216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Visio 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	visio2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Visio 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MV216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Visio 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	visio2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Publisher 2013용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MP213	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Publisher 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	publisher2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Publisher 2013용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MP213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Publisher 2013_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	publisher2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Publisher 2016용 보안 업데이트\(\w{9}\) 32',
            'excel' : '	Q#ki# MP216	#gi#	#ki#	99	WXP,W23,WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Publisher 2016용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	publisher2016-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Publisher 2016용 보안 업데이트\(\w{9}\) 64',
            'excel' : '	Q#ki# MP216_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W212,W81,W212R2,W10,W216		#df1#	#df2#, Microsoft Publisher 2016_x64용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	publisher2016-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft SharePoint Foundation 2013용 보안',
            'excel' : '	Q#ki# MSSPF213_x64	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W81,W212,W212R2,W10,W216		#df1#	#df2#, Microsoft SharePoint Foundation 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	sts2013-KB#ki#-fullfile-x86-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft SharePoint Enterprise Server 2013용 보안',
            'excel' : '	Q#ki# MSSPS213	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W81,W212,W212R2,W10,W216		#df1#	#df2#, Microsoft SharePoint Enterprise Server 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	coreserverloc2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        },
        {
            'regex' : 'Microsoft Office Web Apps Server 2013용 보안',
            'excel' : '	Q#ki# MSOWAS213	#gi#	#ki#	9	WVT,W28,W7,W28R2,W8,W81,W212,W212R2,W10,W216		#df1#	#df2#, Microsoft Office Web Apps Server 2013용 보안 업데이트	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			0	wacserver2013-KB#ki#-fullfile-x64-KOR.exe	1	 /quiet /norestart	!pass!	!pass!	!pass!',
            'group' : 1
        }
    ],
    'internet' : [
        {
            'regex' : 'x86 기반 시스템 Windows 7용 Internet Explorer 11',
            'excel' : '	Q#ki# 7	#gi#	#ki#	0	W7	IE11	#df1#	#df2#, Internet Explorer용 누적 보안 업데이트 (Windows 7 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE11-Windows6.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows 7용 Internet Explorer 11',
            'excel' : '	Q#ki# 7_x64	#gi#	#ki#	9	W7	IE11	#df1#	#df2#, Internet Explorer용 누적 보안 업데이트 (Windows 7_x64 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE11-Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템 Windows 8.1용 Internet Explorer 11',
            'excel' : '	Q#ki# 81	#gi#	#ki#	0	W81	IE11	#df1#	#df2#, Internet Explorer용 누적 보안 업데이트 (Windows 8.1 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows 8.1용 Internet Explorer 11',
            'excel' : '	Q#ki# 81_x64	#gi#	#ki#	9	W81	IE11	#df1#	#df2#, Internet Explorer용 누적 보안 업데이트 (Windows 8.1_x64 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows Server 2008 R2용 Internet Explorer 11',
            'excel' : '	Q#ki# 28R2_x64	#gi#	#ki#	9	W28R2	IE11	#df1#	#df2#, Internet Explorer용 누적 보안 업데이트 (Windows 2008R2_x64 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE11-Windows6.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows Server 2012용 Internet Explorer 11',
            'excel' : '	Q#ki# 212	#gi#	#ki#	9	W212	IE11	#df1#	#df2#, Internet Explorer용 누적 보안 업데이트 (Windows 2012 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	IE11-Windows6.2-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows Server 2012 R2용 Internet Explorer 11',
            'excel' : '	Q#ki# 212R2	#gi#	#ki#	9	W212R2	IE11	#df1#	#df2#, Internet Explorer용 누적 보안 업데이트 (Windows 2012R2 IE11)	http://support.microsoft.com/kb/#ki#	#s#	0	Microsoft			1	Windows8.1-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x86 기반 시스템 Windows Server 2008용 Internet Explorer 9',
            'excel' : '	Q#ki# 28	#gi#	#ki#	0	W28	IE9	#df1#	#df2#, Internet Explorer용 누적 보안 업데이트 (Windows 2008 IE9)	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	IE9-Windows6.0-KB#ki#-x86-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        },
        {
            'regex' : 'x64 기반 시스템 Windows Server 2008용 Internet Explorer 9',
            'excel' : '	Q#ki# 28_x64	#gi#	#ki#	9	W28	IE9	#df1#	#df2#, Internet Explorer용 누적 보안 업데이트 (Windows 2008_x64 IE9)	http://support.microsoft.com/kb/#ki#	0	0	Microsoft			1	IE9-Windows6.0-KB#ki#-x64-KOR.msu	1	 /quiet /norestart	!pass!		',
            'group' : 1
        }
    ]
}

totalRowDic = {
    'windows-cumulative' : {},
    'windows-security' : {},
    'office' : {},
    'internet' : {}
}