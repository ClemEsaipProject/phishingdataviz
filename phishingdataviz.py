import streamlit as st
import requests 

key="xPMrDOlGT6xmGKihu4RQpNXBiDFTauny"
base_url = "https://www.ipqualityscore.com/api/json/url/"+key+"/{}"


about_template = """
<div>
<li>Scores de risque >= 75 - suspect - généralement dû à des modèles associés à des liens malveillants.</li><br>
<li>Les URL suspectes marquées de Suspicious = " true " indiqueront des domaines présentant de fortes chances d'être impliqués dans un comportement abusif.</li><br>
<li>Scores de risque >= 90 – risque élevé – forte confiance dans le caractère malveillant de l’URL.</li><br>
<li>Scores de risque = 100 ET Phishing = " true " OU Malware = " true " - indique une activité confirmée de malware ou de phishing au cours des dernières 24 à 48 heures.</li>
</div>
"""


def get_data(url):
    resp=requests.get(url)
    return resp.json()


def main():
    menu = ["Home","About"]
    choise =st.sidebar.selectbox("Menu",menu)

    st.title("Phishing DATA Visualisation")

    if  choise == "Home":
        st.subheader("Home")

        with st.form(key='searchform'):
            nav1,nav2 = st.columns([2,1])

            with nav1:
                search_url = st.text_input("enter url")
            with nav2:
                st.text("search")
                submit_search = st.form_submit_button(label='Search')

        st.success("you searched for {} " .format(search_url))

        col1,col2 = st.columns([2,1])

        with col1:
            if submit_search :
                url = base_url.format(search_url)
                data=get_data(url)

                st.write(data)
                                
                if data:
    # Récupération des valeurs des clés
                    dns_valid = data.get("dns_valid",False)
                    spam = data.get("spamming", False)
                    malware = data.get("malware",False)
                    phishing = data.get("phishing", False)
                    suspicious = data.get('suspicious',False)
                    risk_score = data.get('risk_score')
                    
    
    # Affichage des valeurs dans Streamlit
                    st.write("DNS : ",dns_valid)
                    st.write("spamming :", spam)
                    st.write("malware :", malware)
                    st.write("phishing :", phishing)
                    st.write("suspicious :", suspicious)
                    st.write('risk_score :',risk_score)

 
    else:
        st.subheader("About")
        st.title("About")
        st.markdown(about_template,unsafe_allow_html=True)



if __name__ == '__main__':
    main()