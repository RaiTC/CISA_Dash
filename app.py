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

# Calculate Summary Metrics
total_kevs = cisa_df.shape[0]
average_epss = cisa_df['EPSS'].mean()
average_cvss = cisa_df['CVSS3'].mean()

# Define severity ranges
def categorize_severity(cvss):
    if cvss == 0:
        return "N/A"
    elif 0.1 <= cvss <= 3.9:
        return "Low"
    elif 4.0 <= cvss <= 6.9:
        return "Medium"
    elif 7.0 <= cvss <= 8.9:
        return "High"
    elif 9.0 <= cvss <= 10.0:
        return "Critical"
    return "N/A"

cisa_df['Severity'] = cisa_df['CVSS3'].apply(categorize_severity)

# Count KEVs by severity
severity_counts = cisa_df['Severity'].value_counts().reset_index()
severity_counts.columns = ['Severity', 'Count']

# KEVs over time (Monthly)
kevs_over_time = cisa_df.groupby(cisa_df['dateAdded'].dt.to_period('M')).size().reset_index(name='Count')
kevs_over_time['dateAdded'] = kevs_over_time['dateAdded'].dt.to_timestamp()

# Prepare data for top 5 vendors/products with KEVs
top_vendors_df = cisa_df['vendorProject'].value_counts().nlargest(5).reset_index()
top_vendors_df.columns = ['Vendor/Project', 'Count']

# Define colors for severity levels
severity_colors = {'Critical': 'darkred', 'High': 'darkorange', 'Medium': 'yellow', 'Low': 'blue'}

# KEVs by Severity (Pie Chart)
severity_pie_fig = px.pie(
    severity_counts,
    names='Severity',
    values='Count',
    title='KEVs by Severity',
    color='Severity',
    color_discrete_map=severity_colors,
    hole=0.4
)

# KEVs Over Time (Line Chart)
kevs_over_time_fig = px.line(
    kevs_over_time,
    x='dateAdded',
    y='Count',
    title='Number of KEVs Added Over Time',
    labels={'dateAdded': 'Date Added', 'Count': 'Number of KEVs'}
)

# Top 5 Vendors/Products with KEVs (Bar Chart)
top_vendors_fig = px.bar(
    top_vendors_df,
    x='Vendor/Project',
    y='Count',
    title='Top 5 Vendors/Products with KEVs',
    labels={'Vendor/Project': 'Vendor/Project', 'Count': 'Number of KEVs'}
)

# Create bar graph for severity
severity_bar_fig = px.bar(
    severity_counts,
    x='Severity',
    y='Count',
    text='Count',
    title='KEV Count by Severity',
    labels={'Severity': 'Severity', 'Count': 'Number of KEVs'},
    color='Severity',
    color_discrete_map=severity_colors
)
severity_bar_fig.update_traces(textposition='outside')

# Create a new column to categorize CVEs for the scatter plot
def highlight_high_severity(row):
    if row['Severity'] in ['High', 'Critical'] and row['EPSS'] > 0.5:
        return 'High Severity'
    return 'Other'

cisa_df['Highlight'] = cisa_df.apply(highlight_high_severity, axis=1)

# CVSS vs EPSS Scatter Plot
scatter_fig = px.scatter(
    cisa_df,
    x='CVSS3',
    y='EPSS',
    color='Highlight',
    title='CVSS Base Scores vs. EPSS Scores',
    labels={'CVSS3': 'CVSS Base Score', 'EPSS': 'EPSS Score'},
    hover_data=['cveID', 'vulnerabilityName']
)

scatter_fig.update_layout(legend_title_text='Category')

# Ensure CVSS3 and EPSS columns are numeric
cisa_df['CVSS3'] = pd.to_numeric(cisa_df['CVSS3'], errors='coerce')
cisa_df['EPSS'] = pd.to_numeric(cisa_df['EPSS'], errors='coerce')

# Calculate the time to remediation for each KEV
cisa_df['time_to_remediate'] = (cisa_df['dueDate'] - cisa_df['dateAdded']).dt.days

# Risk Heatmap
heatmap_fig = px.density_heatmap(
    cisa_df,
    x='CVSS3',
    y='EPSS',
    nbinsx=10,
    nbinsy=10,
    title='Risk Heatmap (CVSS vs EPSS)',
    labels={'CVSS3': 'CVSS Base Score', 'EPSS': 'EPSS Score'}
)

# Risk Comparison by Vendor/Project (Radar Chart)
radar_data = cisa_df.groupby('vendorProject')[['CVSS3', 'EPSS']].mean().reset_index()
radar_fig = px.line_polar(
    radar_data,
    r='CVSS3',
    theta='vendorProject',
    line_close=True,
    title='Risk Comparison by Vendor/Project (CVSS)',
    labels={'CVSS3': 'Average CVSS'}
)

radar_epss_fig = px.line_polar(
    radar_data,
    r='EPSS',
    theta='vendorProject',
    line_close=True,
    title='Risk Comparison by Vendor/Project (EPSS)',
    labels={'EPSS': 'Average EPSS'}
)

# Time to Remediation (Box Plot)
remediation_fig = px.box(
    cisa_df,
    x='Severity',
    y='time_to_remediate',
    title='Time to Remediation by Severity',
    labels={'Severity': 'Severity Level', 'time_to_remediate': 'Time to Remediate (days)'}
)

# Prepare data for Severity Trend Over Time
severity_trend = cisa_df.groupby([cisa_df['dateAdded'].dt.to_period('M'), 'Severity']).size().reset_index(name='Count')
severity_trend['dateAdded'] = severity_trend['dateAdded'].dt.to_timestamp()

# Severity Trend Over Time (Stacked Area Chart)
severity_trend_fig = px.area(
    severity_trend,
    x='dateAdded',
    y='Count',
    color='Severity',
    title='Severity Trend Over Time',
    labels={'dateAdded': 'Date Added', 'Count': 'Number of KEVs'},
    color_discrete_map=severity_colors
)

# Prepare data for Average EPSS Score Over Time
average_epss_trend = cisa_df.groupby(cisa_df['dateAdded'].dt.to_period('M'))['EPSS'].mean().reset_index()
average_epss_trend['dateAdded'] = average_epss_trend['dateAdded'].dt.to_timestamp()

# Average EPSS Score Over Time (Line Chart)
average_epss_trend_fig = px.line(
    average_epss_trend,
    x='dateAdded',
    y='EPSS',
    title='Average EPSS Score Over Time',
    labels={'dateAdded': 'Date Added', 'EPSS': 'Average EPSS Score'}
)

# Layout for the Dashboard page
dashboard_layout = html.Div([
    dbc.Container([
        html.H1("Summary Metrics", className="my-4"),
        dbc.Row([
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H5("Total KEVs", className="card-title"),
                    html.P(f"{total_kevs}", className="card-text")
                ])
            ]), width=3),
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H5("Average EPSS Score", className="card-title"),
                    html.P(f"{average_epss:.2f}", className="card-text")
                ])
            ]), width=3),
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H5("Average CVSS Score", className="card-title"),
                    html.P(f"{average_cvss:.2f}", className="card-text")
                ])
            ]), width=3),
        ]),
        dbc.Row([
            dbc.Col(dcc.Graph(figure=severity_pie_fig), width=6),
            dbc.Col(dcc.Graph(figure=top_vendors_fig), width=6),
        ]),
        dbc.Row([
            dbc.Col(dcc.Graph(figure=kevs_over_time_fig), width=12),
        ]),
        dbc.Row([
            dbc.Col(dcc.Graph(figure=severity_bar_fig), width=12),
        ]),
    ])
])

# Layout for the KEV Database page
kev_database_layout = html.Div([
    dbc.Container([
        html.H1("KEV Database", className="my-4"),
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
        dbc.Input(id="search-input", placeholder="Search KEVs...", type="text", debounce=True),
        html.Br(),
        dbc.Button("Search", id="search-button", color="primary", className="me-1"),
        html.Br(), html.Br(),
        html.Div(id='kev-database-table')
    ])
])

# Layout for the STIR (Severity, Trends, Impact, and Risk) pages
def create_stir_page(title):
    return html.Div([
        dbc.Container([
            html.H1(title, className="my-4"),
            dcc.Graph(id='severity-bar-graph', figure=severity_bar_fig),
            dcc.Graph(id='cvss-epss-scatter-plot', figure=scatter_fig)
        ])
    ])

severity_layout = create_stir_page("Severity")
impact_layout = create_stir_page("Impact")

def create_trends_layout():
    return html.Div([
        dbc.Container([
            html.H1("Trends", className="my-4"),
            dcc.Graph(id='kevs-over-time', figure=kevs_over_time_fig),
            dcc.Graph(id='severity-trend', figure=severity_trend_fig),
            dcc.Graph(id='average-epss-trend', figure=average_epss_trend_fig),
        ])
    ])

trends_layout = create_trends_layout()

def create_risks_layout():
    return html.Div([
        dbc.Container([
            html.H1("Risks", className="my-4"),
            dcc.Graph(id='risk-heatmap', figure=heatmap_fig),
            dbc.Row([
                dbc.Col(dcc.Graph(id='risk-radar-cvss', figure=radar_fig), width=6),
                dbc.Col(dcc.Graph(id='risk-radar-epss', figure=radar_epss_fig), width=6)
            ]),
            dcc.Graph(id='time-to-remediation', figure=remediation_fig),
        ])
    ])

risks_layout = create_risks_layout()

# Define the app layout with a navigation bar
app.layout = html.Div([
    dbc.NavbarSimple(
        brand="Known Vulnerabilities Dashboard",
        brand_href="/",
        color="primary",
        dark=True,
        children=[
            dbc.NavItem(dbc.NavLink("Dashboard", href="/")),
            dbc.NavItem(dbc.NavLink("KEV Database", href="/kev-database")),
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
    if pathname == '/kev-database':
        return kev_database_layout
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

# Callback to update the KEV database table
@app.callback(
    Output('kev-database-table', 'children'),
    [
        Input('search-button', 'n_clicks'),
        Input('search-input', 'n_submit'),
        Input('date-picker-range', 'start_date'),
        Input('date-picker-range', 'end_date'),
        Input('vendor-filter', 'value')
    ],
    State('search-input', 'value')
)
def update_kev_database_table(n_clicks, n_submit, start_date, end_date, selected_vendors, search_value):
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

    # Determine height based on the number of rows (populate low search results accordingly)
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
