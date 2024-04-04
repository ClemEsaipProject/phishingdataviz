# Requirements for a Phishing Prediction Application for Enterprises

## Academic Request - Data Mining Project with Streamlit

### Project Overview and Functional Requirements:
The project aims to develop an application for predicting phishing attacks in enterprises using Data Mining techniques. The goal is to apply the knowledge acquired in data mining to build a robust predictive model.

### Site Objectives:
The application aims to demonstrate the practical application of data mining techniques in the cybersecurity domain by providing an interactive platform for predicting phishing attacks.

### Benchmark:
An analysis of similar tools and techniques will be conducted to understand best practices and the most effective approaches in this field.

### Content:
The application content will include features for data preprocessing, model construction, result visualization, and model performance evaluation.

## Functional Solution

### Target Audience:
The target users of the application are students in computer science, cybersecurity, or data science interested in applying data mining techniques in a real-world context.

### Mobile Web:
The application will be developed using Streamlit, a Python library for creating interactive web applications. It will be accessible via a standard web browser.

### Site Structure:
The organization of pages and functionalities of the application will be structured to allow smooth navigation and intuitive use.

### UML Diagrams:
UML diagrams will be used to model the architecture of the application, including the different layers (user interface, business logic, data access) and their interactions.

## Project Organization

### Resources Allocated to the Project:
Human resources (participating students), hardware resources (computers, servers), and software resources (development environment, Python libraries) will be allocated to successfully carry out the project.

### Technological Choices:
The choice of Streamlit as a development platform will be justified by its ease of use, flexibility, and ability to create interactive web applications using Python code.

### Development and Hosting:
The application development will take place on GitHub, with free hosting of the code. Demo versions will be available online for continuous evaluation of the project.

### Applied Methodology:
An agile methodology will be followed, with 2-hour work sessions per day. One hour will be dedicated to documentation and technological watch, while the other hour will be devoted to actual code development.

### Story Map:
A story map will be developed to define the application features, prioritize them, and track their implementation throughout the project.

### Cost and Revenue:
Development costs will be minimized by using open-source tools and resources wherever possible. The success of the project will be measured by user satisfaction and the quality of the developed predictive model.

### example :
![image](https://github.com/ClemEsaipProject/phishingdataviz/assets/144778367/680ecefb-408e-44a8-b1f2-9c61d8049b3e)

Model Parameters:

This shows the parameters used to train the model, such as the data split ratio (for the training set), the number of estimators and the maximum number of features.

Model Performance:

This section presents model performance on training and test data. Typical metrics include Mean Squared Error (MSE) and coefficient of determination (R-squared).

Feature Importance:

This horizontal bar chart shows the importance of features in predicting the model. Each bar represents a feature, and its length indicates its relative importance in predicting the model. The most important features are generally those with the highest values.

In this case :

The "url_length" feature appears to be the most important, followed by "n_redirection", "n_percent", "n_space", and "n_asterisk".
The value of each feature is plotted on the x-axis, and their importance is plotted on the y-axis.
This suggests that, in this model, URL length is the most important feature for predicting phishing attacks, followed by the number of redirects, the percentage of specific features in the URL, and other features such as spaces and asterisks.

![image](https://github.com/ClemEsaipProject/phishingdataviz/assets/144778367/ce3dbe1c-4494-4b38-bfd8-ff5abd172f2c)

Prediction results :

This is a table showing the prediction results for each data example.

Columns include:

"actual": The actual class for the data example.
"predicted": The prediction made by the model for this data example.
"class: Indicates whether the data example is in the train set or the test set.

Scatter plot:

This scatter plot shows the comparison between the actual values and the values predicted by the model.
Each point represents an example of data.
The points are coloured differently depending on whether they belong to the train or test set.
The x-axis represents the actual values, while the y-axis represents the predicted values.

In this case :

You can see that most of the points are aligned close to the diagonal line, which indicates that the model's predictions are fairly close to the actual values.
The points coloured blue represent the sample data from the test set, while the points coloured grey represent the sample data from the training set.
This suggests that the model appears to generalise well to the test data, which is a positive indication of its ability to accurately predict phishing attacks.


