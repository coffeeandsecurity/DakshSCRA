# Daksh SCRA (Source Code Review Assist)


```
Author: 	
	Debasis Mohanty (d3basis.m0hanty@gmail.com)
	Twitter: @coffeensecurity
	www.coffeeandsecurity.com
```

## About Daksh SCRA
Daksh SCRA (Source Code Review Assist) tool is built to enhance the efficiency of the source code review process, providing a well-structured and organized approach for code reviewers.

Rather than indiscriminately flagging everything as a potential issue, Daksh SCRA promotes thoughtful analysis, urging the investigation and confirmation of potential problems. This approach mitigates the scramble to tag every potential concern as a bug, cutting back on the confusion and wasted time spent on false positives.

What sets Daksh SCRA apart is its emphasis on avoiding unnecessary bug tagging. Unlike conventional methods, it advocates for thorough investigation and confirmation of potential issues before tagging them as bugs. This approach helps mitigate the issue of false positives, which often consume valuable time and resources, thereby fostering a more productive and efficient code review process.

## Debut
Daksh SCRA was initially introduced during a source code review training session I conducted at Black Hat USA 2022 (August 6 - 9), where it was subtly presented to a specific audience. However, this introduction was carried out with a low-profile approach, avoiding any major announcements.

While this tool was quietly published on GitHub after the 2022 training, its official public debut took place at Black Hat USA 2023 in Las Vegas.

## Features and Functionalities
> Although this tool has progressed beyond its early stages, it has reached a functional state that is quite usable and delivers on its promised capabilities. Nevertheless, active enhancements are currently underway, and there are multiple new features and improvements expected to be added in the upcoming months.

The tool currently offers the following functionalities: 
* Options to use platform-specific rules specific for finding areas of interests
* Options to extend or add new rules for any new or existing languages
* Generate a raw output both in text and HTML format for inspection

Feel free to contribute towards updating or adding new rules and future development.

If you find any bugs, report them to d3basis.m0hanty@gmail.com.


Refer to the wiki for the tool setup and usage details - https://github.com/coffeeandsecurity/DakshSCRA/wiki

## Tool Setup

### Pre-requisites
Python3 and all the libraries listed in requirements.txt

### Setting up environment to run this tool

#### 1. Setup a virtual environment
	$ pip install virtualenv

	$ virtualenv -p python3 {name-of-virtual-env}  		// Create a virtualenv
	Example: virtualenv -p python3 venv

	$ source {name-of-virtual-env}/bin/activate 		// To activate virtual environment you just created
	Example: source venv/bin/activate

After running the activate command you should see the name of your virtual env at the beginning of your terminal like this:
	(venv) $ 

#### 2. Ensure all required libraries are installed within the virtual environment
You must run the below command after activating the virtual environment as mentioned in the previous steps.

	pip install -r requirements.txt

Once the above step successfully installs all the required libraries, refer to the following tool usage commands to run the tool.

## Tool Usage

$ python3 dakshscra.py -h		// To view avaialble options and arguments

	usage: dakshscra.py [-h] [-r RULE_FILE] [-f FILE_TYPES] [-v] [-t TARGET_DIR] [-l {R,RF}] [-recon] [-estimate]

	options:
	-h, --help            show this help message and exit
	-r RULE_FILE          Specify platform specific rule name
	-f FILE_TYPES         Specify file types to scan
	-v                    Specify verbosity level {'-v', '-vv', '-vvv'}
	-t TARGET_DIR         Specify target directory path
	-l {R,RF}, --list {R,RF}
							List rules [R] OR rules and filetypes [RF]
	-recon                Detects platform, framework and programming language used
	-estimate             Estimate efforts required for code review

### Example Usage
$ python3 dakshscra.py		// To view tool usage along with examples

	Examples:
	# '-f' is optional. If not specified, it will default to the corresponding filetypes of the selected rule.
	dakshsca.py -r php -t /source_dir_path

	# To override default settings, other filetypes can be specified with '-f' option.
	dakshsca.py -r php -f dotnet -t /path_to_source_dir
	dakshsca.py -r php -f custom -t /path_to_source_dir

	# Perform reconnaissance and rule based scanning if '-recon' used with '-r' option.
	dakshsca.py  -recon -r php -t /path_to_source_dir

	# Perform only reconnaissance if '-recon' used without the '-r' option.
	dakshsca.py  -recon -t /path_to_source_dir

	# Verbosity: '-v' is default, '-vvv' will display all rules check within each rule category.
	dakshsca.py -r php -vv -t /path_to_source_dir


	Supported RULE_FILE: 	dotnet, java, php, javascript
	Supported FILE_TYPES:	dotnet, php, java, custom, allfiles


## Reports
The tool generates reports in three formats: HTML, PDF, and TEXT. Although the HTML and PDF reports are still being improved, they are currently in a reasonably good state. With each subsequent iteration, these reports will continue to be refined and improved even further.

### Scanning Report
###### HTML Report:
* DakshSCRA/reports/html/report.html	
###### PDF Report:
* DakshSCRA/reports/html/report.pdf
###### RAW TEXT Based Reports: 	
* Areas of Interest - Identified Patterns : 	DakshSCRA/reports/text/areas_of_interest.txt
* Areas of Interest - Project Files: 	DakshSCRA/reports/text/filepaths_aoi.txt
* Identified Project Files:		DakshSCRA/runtime/filepaths.txt	

### Reconnaissance (Recon) Report
* Reconnaissance Summary: /reports/text/recon.txt

Note: Currently, the reconnaissance report is created in a text format. However, in upcoming releases, the plan is to incorporate it into the vulnerability scanning report, which will be available in both HTML and PDF formats.


### Code Review Effort Estimation Report
* Effort estimation report: /reports/html/estimation.html

Note: At present, the effort estimation for the source code review is in its early stages. It is considered experimental and will be developed and refined through several iterations. Improvements will be made over multiple releases, as the formula and the concept are new and require time to be honed to achieve accuracy or reasonable estimation.

Currently, the report is generated in HTML format. However, in future releases, there are plans to also provide it in PDF format.

