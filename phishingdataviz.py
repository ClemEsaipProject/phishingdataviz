import streamlit as st
import requests
from streamlit_keplergl import keplergl_static
from keplergl import KeplerGl
from geopy.geocoders import Nominatim
import pandas as pd
import json

key = "xPMrDOlGT6xmGKihu4RQpNXBiDFTauny"
base_url = "https://www.ipqualityscore.com/api/json/url/" + key + "/{}"
base_email= "https://www.ipqualityscore.com/api/json/email/"+key+"/{}"
geolocator = Nominatim(user_agent="my_app")
country_code_url="https://www.ipqualityscore.com/api/json/country/list"

about_template = """
<div>
<li>Scores de risque >= 75 - suspect - généralement dû à des modèles associés à des liens malveillants.</li><br>
<li>Les URL suspectes marquées de Suspicious = " true " indiqueront des domaines présentant de fortes chances d'être impliqués dans un comportement abusif.</li><br>
<li>Scores de risque >= 90 – risque élevé – forte confiance dans le caractère malveillant de l’URL.</li><br>
<li>Scores de risque = 100 ET Phishing = " true " OU Malware = " true " - indique une activité confirmée de malware ou de phishing au cours des dernières 24 à 48 heures.</li>
</div>
"""


def get_data(url):
    resp = requests.get(url)
    return resp.json()


def get_coordinates(country_code):
    location = geolocator.geocode(country_code)
    if location:
        return location.latitude, location.longitude
    else:
        return None, None


def main():
    menu = ["Home","Email","IP", "About"]
    choise = st.sidebar.selectbox("Menu", menu)

    st.title("Phishing DATA Visualisation")

    if choise == "Home":
        st.subheader("Home")

        with st.form(key="searchform"):
            nav1, nav2 = st.columns([2, 1])

            with nav1:
                search_url = st.text_input("enter url")
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

    elif choise == "IP":
        st.subheader("IP")

        with st.form(key="searchform"):
            nav1, nav2 = st.columns([2, 1])

            with nav1:
                search_url = st.text_input("enter IP address")
            with nav2:
                st.text("search")
                submit_search = st.form_submit_button(label="Search")

        st.success("you searched for {} ".format(search_url))


    else:
        st.subheader("About")
        st.title("About")
        st.markdown(about_template, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
