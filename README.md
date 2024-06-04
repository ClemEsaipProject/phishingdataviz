# Requirements for a URL Scanning and Threat Detection Application

## Academic Request - Data Mining Project with Streamlit

### Project Overview and Functional Requirements:
The project aims to develop an application for scanning URLs and determining their affiliation with various threat categories, including DNS validation, spam, malware, phishing, suspicious activity, and risk score calculation.

### Objectives of the Application:
The primary objective of the application is to provide users with a tool to assess the security risks associated with a given URL by leveraging data mining techniques.

### Content:
The application will include features for URL scanning, threat detection, and risk assessment. It will provide detailed reports on the identified threats and associated risk scores. The application will utilize the APIs provided by [IPQualityScore](https://www.ipqualityscore.com/) and [VirusTotal](https://www.virustotal.com/) for accessing threat intelligence data and validating URLs against known threat databases.

## Functional Solution

### Target Audience:
The target users of the application are individuals and organizations concerned with cybersecurity, including cybersecurity professionals, IT administrators, and general users seeking to verify the security of URLs.

### Mobile Web:
The application will be developed using Streamlit, a Python library for creating interactive web applications. It will be accessible via standard web browsers, making it suitable for both desktop and mobile use.

### Site Structure:
The application interface will be designed to facilitate easy navigation and intuitive use. Users will be able to input URLs for scanning and view detailed threat reports.

### Model Parameters and Performance:
The application will utilize machine learning models for threat detection and risk assessment. Model parameters and performance metrics, such as accuracy, precision, and recall, will be presented to users for transparency and evaluation.

### API Integration:
The application will integrate with external APIs for accessing threat intelligence data and validating URLs against known threat databases. This integration will ensure access to up-to-date threat information and enhance the accuracy of threat detection. Specifically, it will use the IPQualityScore and VirusTotal APIs.

### VirusTotal API Integration:
VirusTotal provides a comprehensive URL scanning service that aggregates results from multiple antivirus engines and website scanners. The application will use VirusTotal to:

- Scan URLs and check them against various threat databases.
- Retrieve detailed reports on detected threats, including phishing, malware, and other malicious activities.
- Visualize the results using graphs to help users understand the security status of the scanned URLs.

### Documentation and Support:
Comprehensive documentation will be provided to guide users on the use of the application and interpretation of threat reports. Additionally, user support channels, such as FAQs and community forums, will be established to address user inquiries and feedback.

### Cost and Revenue:
The application will be freely available for use, with no cost to users. Revenue generation may be explored through partnerships, sponsorships, or premium features in the future, but the primary focus will be on delivering value to users and promoting cybersecurity awareness.

## Example:
![image](https://github.com/ClemEsaipProject/phishingdataviz/assets/144778367/d71d2cd0-c492-4404-a6e4-8dcc4bbc692e)
*real site* 

![image](https://github.com/ClemEsaipProject/phishingdataviz/assets/144778367/b09dd075-6c4e-41f9-88e2-f1e1b59c4b82)
~~fake site~~

## Installation

### Prérequis

- Python 3.6 ou plus
- pip (Python package installer)

### Cloner le dépôt

```bash
git clone https://github.com/ClemEsaipProject/phishingdataviz.git
cd votre-projet
```

Installer les dépendances
```bash
pip install -r requirements.txt
```

Configuration des API
Créez un fichier .env à la racine du projet et ajoutez vos clés API :
```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
EMAILREP_API_KEY=your_emailrep_api_key
```

Utilisation
Pour démarrer l'application, exécutez la commande suivante :
```bash
streamlit run app.py
```
Naviguez ensuite vers http://localhost:8501 dans votre navigateur.

Fonctionnalités
Scan d'URLs : Entrez une URL pour la scanner avec VirusTotal et obtenir des informations sur sa réputation.
Visualisation des données : Affichage des résultats de scan sous forme de graphique camembert.
Support multi-API : Intégration des API VirusTotal et EmailRep.
Exemples d'utilisation
Scan d'une URL
Lancez l'application.
Entrez l'URL dans le champ de saisie.
Cliquez sur "Scan".
Visualisez les résultats sous forme de graphique.
