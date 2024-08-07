# ✨ XNP - Xtreme Nmap Parser
Xtreme Nmap Parser (XNP) is a Python-based utility designed to parse XML files generated by Nmap, a powerful network scanning tool. XNP allows you to convert these XML files into other useful formats, such as CSV/XLSX/JSON.

<!-- TOC -->
* [✨ XNP - Xtreme Nmap Parser](#-xnp---xtreme-nmap-parser)
  * [⭐ Features](#-features)
  * [💥 Key Benefits](#-key-benefits)
* [💻 Install](#-install)
* [🎓 Usage](#-usage)
* [🛠️ Configuration](#-configuration)
* [💬 Change Log](#-change-log)
* [📜 License](#-license)
* [🎉 Let's Get Social!](#-lets-get-social-)
<!-- TOC -->

![xnp_scheme.png](resources%2Fimages%2Fxnp_scheme.png)

![excel_example.png](resources%2Fimages%2Fexcel_example_1.png)

## ⭐ Features
- Parse Nmap XML files.
- Export parsed data to CSV/XLSX/JSON formats.
- Handle a single file or a directory of XML files.
- Configurable output formats and other settings through a YAML configuration file.

## 💥 Key Benefits

- **Filtering Options:** Filter based on specific services or open ports to concentrate on targets of interest while disregarding irrelevant data.
- **Pentest Records:** Keeping track of analyzed data can be beneficial to avoid unnecessary re-scanning, monitor progress over time, and provide an audit trail for review purposes.
- **Network-Wide Vulnerability Detection:** If a vulnerable service is detected on one host, XNP can be used to swiftly search for other hosts in the network potentially running the same service, assisting in identifying vulnerabilities across the network.
- **Easy Data Export:** The ability to effortlessly copy and paste data about vulnerable hosts, filtered by service version, can be a practical feature. It simplifies the documentation of findings, data sharing with colleagues, and inputting data into other tools or reports.

# 💻 Install

The installation information can be found in the '[Install](https://github.com/xtormin/XtremeNmapParser/wiki/%5BEN%5D-Wiki#install)' section of the wiki.

# 🎓 Usage

The usage information can be found in the '[Usage](https://github.com/xtormin/XtremeNmapParser/wiki/%5BEN%5D-Wiki#usage)' section of the wiki.

My favorite example:

```
python3 xnp.py -d nmap/ -M -R --open -C all
```

# 🛠️ Configuration

You can change the output formats and other settings through the [config.yaml](config%2Fconfig.yaml)  file.

# 💬 Change Log
- **24/06/2023** - XNP v1.0.5
  - Updated column argument format. It now accepts "default" and "all" options. Using "default" will select a predefined set of columns, while "all" will select all available columns. The columns for each case are defined in "config.yaml".
- **24/06/2023** - XNP v1.0.4
  - Refactor "outputformat" and "outputname" arguments.
- **24/06/2023** - XNP v1.0.3
  - Added a module for automatic version checking and updating. XtremeNmapParser will now check if it's running the latest version at startup and update itself if a new version is available.
- **13/06/2023** - XNP v1.0.2
  - Added custom headers.
  - New "Scripts" optional column.
  - Export only open ports.
- **07/06/2023** - XNP v1.0.1
  - Refactored code.
  - Introduced NmapXMLReport.py class for XML data parsing.
  - Added recursive option.
- **05/06/2023** - XNP v1.0.0 - Official release.

# TO DO
- [ ] Output file with xml not parsed.
- 

# 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for more information.

# 🎉 Let's Get Social!

* **Website:** [https://xtormin.com](https://xtormin.com)
* **Linkedin:** [https://www.linkedin.com/in/xtormin/](https://www.linkedin.com/in/xtormin/)
* **Twitter:** [https://twitter.com/xtormin](https://twitter.com/xtormin)
* **Youtube:** [https://www.youtube.com/channel/UCZs7q5QeyXS5YmUq6lexozw](https://www.youtube.com/channel/UCZs7q5QeyXS5YmUq6lexozw)
* **Instagram:** [https://www.instagram.com/xtormin/](https://www.instagram.com/xtormin/)