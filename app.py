import dash
import dash_bootstrap_components as dbc
from dash import dcc, html, Input, Output, State
import pandas as pd
import plotly.express as px
from data_fetcher import fetch_cisa_data, process_cisa_data

# Initialize the Dash app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP], suppress_callback_exceptions=True)

# Fetch and process data
cisa_data = fetch_cisa_data()
cisa_df = process_cisa_data(cisa_data)

# Prepare data for bar chart
top_vendors_df = cisa_df['vendorProject'].value_counts().nlargest(5).reset_index()
top_vendors_df.columns = ['Vendor/Project', 'Count']

# Layout for the Dashboard page
dashboard_layout = html.Div([
    dbc.Container([
        html.H1("Dashboard", className="my-4"),
        dbc.Row([
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H5("Total CVEs", className="card-title"),
                    html.P(f"{cisa_df.shape[0]}", className="card-text")
                ])
            ]), width=3),
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H5("Unresolved CVEs", className="card-title"),
                    html.P(f"{cisa_df[cisa_df['dueDate'] > pd.Timestamp.now()].shape[0]}", className="card-text")
                ])
            ]), width=3),
        ]),
        dbc.Row([
            dbc.Col(dcc.Graph(
                figure=px.bar(
                    top_vendors_df,
                    x='Vendor/Project', y='Count',
                    labels={'Vendor/Project': 'Vendor/Project', 'Count': 'Number of CVEs'},
                    title='Top 5 Vendors/Projects with the Most CVEs'
                )
            ), width=6),
        ])
    ])
])

# Layout for the CVE Database page
cve_database_layout = html.Div([
    dbc.Container([
        html.H1("CVE Database", className="my-4"),
        dcc.DatePickerRange(
            id='date-picker-range',
            start_date=cisa_df['dateAdded'].min().date(),
            end_date=cisa_df['dateAdded'].max().date(),
            display_format='YYYY-MM-DD'
        ),
        html.Br(), html.Br(),
        dcc.Dropdown(
            id='vendor-filter',
            options=[{'label': vendor, 'value': vendor} for vendor in cisa_df['vendorProject'].unique()],
            multi=True,
            placeholder='Filter by Vendor/Project'
        ),
        html.Br(),
        dbc.Input(id="search-input", placeholder="Search CVEs...", type="text"),
        html.Br(),
        dbc.Button("Search", id="search-button", color="primary", className="me-1"),
        html.Br(), html.Br(),
        html.Div(id='cve-database-table')
    ])
])

# Define the app layout with a navigation bar
app.layout = html.Div([
    dbc.NavbarSimple(
        brand="CVE Dashboard",
        brand_href="/",
        color="primary",
        dark=True,
        children=[
            dbc.NavItem(dbc.NavLink("Dashboard", href="/")),
            dbc.NavItem(dbc.NavLink("CVE Database", href="/cve-database"))
        ]
    ),
    dcc.Location(id='url', refresh=False),
    html.Div(id='page-content')
])

# Callback to update the page content
@app.callback(Output('page-content', 'children'), [Input('url', 'pathname')])
def display_page(pathname):
    if pathname == '/cve-database':
        return cve_database_layout
    else:
        return dashboard_layout

# Define a dictionary to rename columns
column_rename_dict = {
    "cveID": "CVE ID",
    "vendorProject": "Vendor/Project",
    "product": "Product",
    "vulnerabilityName": "Vulnerability Name",
    "dateAdded": "Date Added",
    "shortDescription": "Description",
    "requiredAction": "Required Action",
    "dueDate": "Due Date",
    "knownRansomwareCampaignUse": "Known Ransomware Use",
    "notes": "Notes",
    "cwes": "CWEs"
}

# Callback to update the CVE database table
@app.callback(
    Output('cve-database-table', 'children'),
    [
        Input('search-button', 'n_clicks'),
        Input('date-picker-range', 'start_date'),
        Input('date-picker-range', 'end_date'),
        Input('vendor-filter', 'value')
    ],
    State('search-input', 'value')
)
def update_cve_database_table(n_clicks, start_date, end_date, selected_vendors, search_value):
    filtered_df = cisa_df.copy()
    
    # Filter by date
    if start_date and end_date:
        filtered_df = filtered_df[(filtered_df['dateAdded'] >= start_date) & (filtered_df['dateAdded'] <= end_date)]
    
    # Filter by vendors
    if selected_vendors:
        filtered_df = filtered_df[filtered_df['vendorProject'].isin(selected_vendors)]
    
    # Search functionality
    if search_value:
        filtered_df = filtered_df[
            filtered_df.apply(lambda row: row.astype(str).str.contains(search_value, case=False).any(), axis=1)
        ]
    
    # Rename columns
    filtered_df = filtered_df.rename(columns=column_rename_dict)
    
    return dbc.Table.from_dataframe(filtered_df, striped=True, bordered=True, hover=True)

if __name__ == '__main__':
    app.run_server(debug=True)
