import dash
import dash_bootstrap_components as dbc
from dash import dcc, html, Input, Output, State, dash_table
import pandas as pd
import plotly.express as px
from data_fetcher import get_latest_data

# Initialize the Dash app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP], suppress_callback_exceptions=True)

# Fetch and process data
cisa_df = get_latest_data()

# Convert non-supported types (like lists, CWEs) to strings
def convert_to_string(df):
    for col in df.columns:
        if df[col].apply(lambda x: isinstance(x, (list, dict))).any():
            df[col] = df[col].apply(str)
    return df

cisa_df = convert_to_string(cisa_df)

# Prepare data for bar chart
top_vendors_df = cisa_df['vendorProject'].value_counts().nlargest(5).reset_index()
top_vendors_df.columns = ['Vendor/Project', 'Count']

# Calculate Summary Metrics
total_cves = cisa_df.shape[0]
high_severity_cves = cisa_df[cisa_df['CVSS3'] >= 7.0].shape[0]
upcoming_due_dates = cisa_df[(cisa_df['dueDate'] <= pd.Timestamp.now() + pd.DateOffset(days=7)) & (cisa_df['dueDate'] >= pd.Timestamp.now())].shape[0]

# Layout for the Dashboard page
dashboard_layout = html.Div([
    dbc.Container([
        html.H1("Vulnerability Management Dashboard", className="my-4"),
        dbc.Row([
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H5("Total CVEs", className="card-title"),
                    html.P(f"{total_cves}", className="card-text")
                ])
            ]), width=3),
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H5("High Severity CVEs", className="card-title"),
                    html.P(f"{high_severity_cves}", className="card-text")
                ])
            ]), width=3),
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H5("Upcoming Due Dates", className="card-title"),
                    html.P(f"{upcoming_due_dates}", className="card-text")
                ])
            ]), width=3),
        ]),
        dbc.Row([
            dbc.Col(dcc.Graph(
                figure=px.bar(
                    top_vendors_df,
                    x='Vendor/Project', y='Count',
                    labels={'Vendor/Project': 'Vendor/Project', 'Count': 'Number of CVEs'},
                    title='Top 5 Vendors/Projects with the Most KEVs'
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
        dbc.Input(id="search-input", placeholder="Search CVEs...", type="text", debounce=True),
        html.Br(),
        dbc.Button("Search", id="search-button", color="primary", className="me-1"),
        html.Br(), html.Br(),
        html.Div(id='cve-database-table')
    ])
])

# Layout for the STIR (Severity, Trends, Impact, and Risk) pages
def create_stir_page(title):
    return html.Div([
        dbc.Container([
            html.H1(title, className="my-4"),
        ])
    ])

severity_layout = create_stir_page("Severity")
trends_layout = create_stir_page("Trends")
impact_layout = create_stir_page("Impact")
risks_layout = create_stir_page("Risks")

# Define the app layout with a navigation bar
app.layout = html.Div([
    dbc.NavbarSimple(
        brand="Vulnerability Management Dashboard",
        brand_href="/",
        color="primary",
        dark=True,
        children=[
            dbc.NavItem(dbc.NavLink("Dashboard", href="/")),
            dbc.NavItem(dbc.NavLink("CVE Database", href="/cve-database")),
            dbc.DropdownMenu(
                label="STIR",
                children=[
                    dbc.DropdownMenuItem("Severity", href="/stir/severity"),
                    dbc.DropdownMenuItem("Trends", href="/stir/trends"),
                    dbc.DropdownMenuItem("Impact", href="/stir/impact"),
                    dbc.DropdownMenuItem("Risks", href="/stir/risks")
                ],
                nav=True,
                in_navbar=True
            )
        ]
    ),
    dcc.Location(id='url', refresh=False),
    html.Div(id='page-content')
])

# Callbacks to update the page content
@app.callback(Output('page-content', 'children'), [Input('url', 'pathname')])
def display_page(pathname):
    if pathname == '/cve-database':
        return cve_database_layout
    elif pathname == '/stir/severity':
        return severity_layout
    elif pathname == '/stir/trends':
        return trends_layout
    elif pathname == '/stir/impact':
        return impact_layout
    elif pathname == '/stir/risks':
        return risks_layout
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
    "cwes": "CWEs",
    "EPSS": "EPSS",
    "CVSS3": "CVSS Base Score"
}

# Callback to update the CVE database table
@app.callback(
    Output('cve-database-table', 'children'),
    [
        Input('search-button', 'n_clicks'),
        Input('search-input', 'n_submit'),
        Input('date-picker-range', 'start_date'),
        Input('date-picker-range', 'end_date'),
        Input('vendor-filter', 'value')
    ],
    State('search-input', 'value')
)
def update_cve_database_table(n_clicks, n_submit, start_date, end_date, selected_vendors, search_value):
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
    
    # Convert any non-supported types to strings
    filtered_df = convert_to_string(filtered_df)

    # Determine height based on the number of rows (populate low search reasults accordingly)
    max_height = "500px"
    if len(filtered_df) <= 5:
        height = "auto"
    else:
        height = max_height
    
    # Create table with auto width adjustment using dash.dash_table.DataTable
    return dash_table.DataTable(
        data=filtered_df.to_dict('records'),
        columns=[{"name": i, "id": i} for i in filtered_df.columns],
        style_table={'overflowX': 'auto', 'width': '100%', 'height': height, 'maxHeight': max_height},
        style_cell={
            'textAlign': 'left',
            'whiteSpace': 'normal',
            'height': 'auto',
            'overflow': 'hidden',
            'textOverflow': 'ellipsis',
            'minWidth': '100px',
            'maxWidth': '150px',
        },

        # Wider boxes for larger data entry
        style_data_conditional=[
            {
                'if': {'column_id': 'Description'},
                'whiteSpace': 'normal',
                'height': 'auto',
                'minWidth': '300px',
                'maxWidth': '500px',
            },
            {
                'if': {'column_id': 'Required Action'},
                'whiteSpace': 'normal',
                'height': 'auto',
                'minWidth': '300px',
                'maxWidth': '500px',
            },
            {
                'if': {'column_id': 'Notes'},
                'whiteSpace': 'normal',
                'height': 'auto',
                'minWidth': '300px',
                'maxWidth': '500px',
            }
        ],
        tooltip_data=[
            {
                column: {'value': str(value), 'type': 'markdown'}
                for column, value in row.items()
            } for row in filtered_df.to_dict('records')
        ],
        tooltip_duration=None,  # Keep tooltips open until mouseout
        page_size=15  # Number of rows per page
    )

if __name__ == '__main__':
    app.run_server(debug=True)
