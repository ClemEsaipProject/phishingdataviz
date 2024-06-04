import streamlit as st
from functions import get_data, get_coordinates,geolocator,get_url_report_virustotal,scan_url_virustotal,base_url,base_email,country_code_url,plot_virustotal_data
from streamlit_keplergl import keplergl_static
from keplergl import KeplerGl
import pandas as pd
import json




about_template = """
<div>
<li>Scores de risque >= 75 - suspect - généralement dû à des modèles associés à des liens malveillants.</li><br>
<li>Les URL suspectes marquées de Suspicious = " true " indiqueront des domaines présentant de fortes chances d'être impliqués dans un comportement abusif.</li><br>
<li>Scores de risque >= 90 – risque élevé – forte confiance dans le caractère malveillant de l’URL.</li><br>
<li>Scores de risque = 100 ET Phishing = " true " OU Malware = " true " - indique une activité confirmée de malware ou de phishing au cours des dernières 24 à 48 heures.</li>
</div>
"""





def main():
    menu = ["Home","Email","VirusTotal", "About"]
    choise = st.sidebar.selectbox("Menu", menu)

    st.title("Phishing DATA Visualisation")

    if choise == "Home":
        st.subheader("Home")

        with st.form(key="searchform"):
            nav1, nav2 = st.columns([2, 1])

            with nav1:
                search_url = st.text_input("enter url for IpQualityScore")
            with nav2:
                st.text("search")
                submit_search = st.form_submit_button(label="Search")

        st.success("you searched for {} ".format(search_url))

        col1, col2 = st.columns([1,1],gap="small")

        with col1:
            if submit_search:
                url = base_url.format(search_url)
                url_country = country_code_url.format(search_url)
                data = get_data(url)
                data_c =get_data(url_country)

                # datas = pd.json_normalize(data)
                st.sidebar.write(data)
                # st.sidebar.write(data_c)
                vt_scan_result = scan_url_virustotal(search_url)
                if vt_scan_result.get('scan_id'):
                    vt_report = get_url_report_virustotal(vt_scan_result.get('scan_id'))

                if data:
                    # Récupération des valeurs des clés
                    dns_valid = data.get("dns_valid", False)
                    spam = data.get("spamming", False)
                    malware = data.get("malware", False)
                    phishing = data.get("phishing", False)
                    suspicious = data.get("suspicious", False)                 

    
                    # Affichage des valeurs dans Streamlit
                    st.write("DNS : ", dns_valid)
                    st.write("spamming :", spam)
                    st.write("malware :", malware)
                    st.write("phishing :", phishing)
                    st.write("suspicious :", suspicious)
                
                  # Display VirusTotal Data
                if vt_report:
                    st.write("VirusTotal Data")
                    for scan in vt_report.get('scans', {}):
                        result = vt_report['scans'][scan]['result']
                        st.sidebar.write(f"{scan}: {result}")

            # Cross-data analysis
                if data and vt_report:
                    st.write("Cross-data Analysis")
                    vt_malicious = any(scan['detected'] for scan in vt_report.get('scans', {}).values())
                    if malware or vt_malicious:
                        st.write("This URL is reported as malware by one or both services.")
                    if phishing or vt_report.get('positives', 0) > 0:
                        st.write("This URL is reported as phishing by one or both services.")
                    if suspicious:
                        st.write("IPQualityScore indicates this URL is suspicious.")

                    

                    
        with col2:
            if submit_search:
                url = base_url.format(search_url)
                url_country = country_code_url.format(search_url)
                data = get_data(url)
                data_c =get_data(url_country)

                # datas = pd.json_normalize(data)
                #st.sidebar.write(data)
                # st.sidebar.write(data_c)

                if data:
                    # Récupération des valeurs des clés
                    
                    risk_score = data.get("risk_score")
                    domain_rank = data.get("domain_rank")
                    country_code = data.get("country_code")
                    category = data.get("category")
                    domain_age = data.get("domain-age ")
                    content_type = data.get("content_type")

                    
                    # Affichage des valeurs dans Streamlit
                    
                    st.write("risk_score :", risk_score)
                    st.write("domain_rank :", domain_rank)
                    st.write("country_code :", country_code)
                    st.write("category :", category)
                    st.write("domain_age :", domain_age)
                    st.write("content_type :", content_type)
           
        if submit_search and data:
                
                # Vérifie si la valeur de 'country_code' est un dictionnaire
                
                if isinstance(data, dict):
                    # Si value est un dictionnaire, accédez à l'élément "country_code"
                    country_code = data.get("country_code")
                    if country_code:
                        latitude, longitude = get_coordinates(country_code)
                        coordinate = pd.json_normalize(
                            {"latitude": latitude, "longitude": longitude}
                        )
                        # st.write(latitude)
                        # st.write(longitude)

                        # coordinate_json =json.dumps(coordinate)

                        # st.dataframe(coordinate)
                        maps = KeplerGl()
                        # Ajout des données à la carte
                        maps.add_data(data=coordinate, name="location")
                        maps.config = {
                            "version": "v1",
                            "config": {
                                "mapState": {
                                    "bearing": 0,
                                    "latitude": 52.52,
                                    "longitude": 13.4,
                                    "pitch": 0,
                                    "zoom": 10,
                                }
                            },
                        }

                        
                        # maps.config = config
                        # Affichage de la carte dans Streamlit
                        keplergl_static(maps, width=800, center_map=True)
                    else:
                        # Si value n'est pas un dictionnaire, faites quelque chose d'autre
                        pass
    elif choise == "Email":
        st.subheader("Email")

        with st.form(key="searchform"):
            nav1, nav2 = st.columns([2, 1])

            with nav1:
                search_email = st.text_input("enter email")
            with nav2:
                st.text("search")
                submit_search = st.form_submit_button(label="Search")

        st.success("you searched for {} ".format(search_email))

        if submit_search:
                url = base_email.format(search_email)
                data = get_data(url)
                

                # datas = pd.json_normalize(data)
                st.sidebar.write(data)
                # st.sidebar.write(data_c)

    elif choise == "VirusTotal":
        st.subheader("VirusTotal")

        with st.form(key="searchform"):
            nav1, nav2 = st.columns([2, 1])

            with nav1:
                search_url = st.text_input("Enter URL for VirusTotal scan")
            with nav2:
                st.text("Search")
                submit_search = st.form_submit_button(label="Search")

        st.success("You searched for {}".format(search_url))

        if submit_search:
            # VirusTotal Data
            vt_scan_result = scan_url_virustotal(search_url)
            st.write("VirusTotal Scan Result:", vt_scan_result)

            if vt_scan_result.get('scan_id'):
                vt_report = get_url_report_virustotal(vt_scan_result.get('scan_id'))
                st.write("VirusTotal URL Report:", vt_report)

                plt = plot_virustotal_data(vt_report)
                st.pyplot(plt)


    else:
        st.subheader("About")
        st.title("About")
        st.markdown(about_template, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
