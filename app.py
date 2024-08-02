import dash
import dash_bootstrap_components as dbc
from dash import dcc, html, Input, Output, State, dash_table, Patch
import pandas as pd
import plotly.express as px
import plotly.io as pio
from data_fetcher import get_latest_data

# Initialize the Dash app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP], suppress_callback_exceptions=True)

# Fetch and process data
cisa_df = get_latest_data()

# Ensure dateAdded is a datetime column
cisa_df['dateAdded'] = pd.to_datetime(cisa_df['dateAdded'])

# ====== Helper Functions ======
# Convert non-supported types (like lists, CWEs) to strings
def convert_to_string(df):
    for col in df.columns:
        if df[col].apply(lambda x: isinstance(x, (list, dict))).any():
            df[col] = df[col].apply(str)
    return df

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

cisa_df = convert_to_string(cisa_df)
cisa_df['Severity'] = cisa_df['CVSS3'].apply(categorize_severity)
severity_colors = {
    'Critical': 'rgb(235, 99, 93)', # Dark Red
    'High': 'rgb(240, 150, 90)',    # Dark Orange
    'Medium': 'rgb(244, 219, 106)', # Yellow
    'Low': 'rgb(148, 215, 106)',    # Green
}

# Calculate combined risk score as the sum of CVSS3 and EPSS
cisa_df['CombinedRisk'] = cisa_df['CVSS3'] + cisa_df['EPSS']

# Calculate Summary Metrics
total_kevs = cisa_df.shape[0]
average_epss = cisa_df['EPSS'].mean()
average_cvss = cisa_df['CVSS3'].mean()

# Risk by Vendor DataFrame
risk_by_vendor_df = cisa_df.groupby('vendorProject').agg({'CombinedRisk': 'mean'}).reset_index()

# Top 5 vendors/projects with the highest average combined risk scores
top_vendors = risk_by_vendor_df.nlargest(5, 'CombinedRisk')

# Top 5 most severe KEVs DataFrame
top_5_severe_kevs = cisa_df.nlargest(5, 'CVSS3')[['cveID', 'vulnerabilityName', 'EPSS', 'CVSS3', 'Severity']]

# Convert DataFrame to dictionary for dash_table
top_5_severe_kevs_dict = top_5_severe_kevs.to_dict('records')

# Severity count by vendor/project
severity_by_vendor = cisa_df.groupby(['vendorProject', 'Severity']).size().reset_index(name='CVE Count')


# ====== Data Graphs ======
# * Dashboard Page *
# KEVs Risk Trend Over Time
risk_trend_df = cisa_df.groupby(cisa_df['dateAdded'].dt.to_period('M')).agg({'CombinedRisk': 'mean'}).reset_index()
risk_trend_df['dateAdded'] = risk_trend_df['dateAdded'].dt.to_timestamp()
risk_trend_fig = px.line(
    risk_trend_df,
    x='dateAdded',
    y='CombinedRisk',
    title='KEVs Risk Trend Over Time',
    labels={'dateAdded': 'Date Added', 'CombinedRisk': 'Average Combined Risk Score'}
)

# KEVs by Severity (Pie Chart)
severity_counts = cisa_df['Severity'].value_counts().reset_index()
severity_counts.columns = ['Severity', 'Count']
severity_pie_fig = px.pie(
    severity_counts,
    names='Severity',
    values='Count',
    title='KEVs by Severity',
    color='Severity',
    color_discrete_map=severity_colors,
    hole=0.4
)
# KEVs by Severity (Bar Chart)
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

# Top 10 Vendors/Products by KEVs (Bar Chart)
top_vendors_df = cisa_df['vendorProject'].value_counts().nlargest(10).reset_index()
top_vendors_df.columns = ['Vendor/Project', 'Count']
custom_color = ['rgb(1, 39, 67, 10)']
top_vendors_fig = px.bar(
    top_vendors_df,
    x='Vendor/Project',
    y='Count',
    title='Top 10 Vendors/Products by KEVs',
    labels={'Vendor/Project': 'Vendor/Project', 'Count': 'Number of KEVs'},
    color_discrete_sequence=custom_color
)

# * Severity Page *
# Create Data Table for Top 5 Most Severe KEVs
top_5_severe_kevs_table = dash_table.DataTable(
    data=top_5_severe_kevs_dict,
    columns=[
        {"name": "CVE ID", "id": "cveID"},
        {"name": "Vulnerability Name", "id": "vulnerabilityName"},
        {"name": "EPSS Score", "id": "EPSS"},
        {"name": "CVSS Score", "id": "CVSS3"},
        {"name": "Severity", "id": "Severity"}
    ],
    style_table={'overflowX': 'auto'},
    style_cell={'textAlign': 'left', 'whiteSpace': 'normal', 'height': 'auto'},
    style_header={'backgroundColor': 'rgb(230, 230, 230)', 'fontWeight': 'bold'}
)

# Stacked Bar Chart: Severity by Vendor/Project
severity_by_vendor_paginated_fig = px.bar(
    severity_by_vendor,
    x='vendorProject',
    y='CVE Count',
    color='Severity',
    title='CVE Count by Severity for Each Vendor/Project',
    labels={'vendorProject': 'Vendor/Project', 'CVE Count': 'Number of CVEs'},
    color_discrete_map=severity_colors
)
severity_by_vendor_paginated_fig.update_layout(
    barmode='stack', 
    xaxis={'categoryorder': 'total descending'}, 
    showlegend=True, 
    xaxis_tickangle=-45,
    height=600,
    margin=dict(l=20, r=20, t=40, b=150)
)

# CVSS vs EPSS Scatter Plot
def highlight_high_severity(row):
    if row['Severity'] in ['High', 'Critical'] and row['EPSS'] > 0.5:
        return 'High Severity'
    return 'Other'

cisa_df['Highlight'] = cisa_df.apply(highlight_high_severity, axis=1)
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

# * Trends Page *
# Multi-line graph: Average EPSS and CVSS Scores Over Time
average_scores_trend = cisa_df.groupby(cisa_df['dateAdded'].dt.to_period('M')).agg({'EPSS': 'mean', 'CVSS3': 'mean'}).reset_index()
average_scores_trend['dateAdded'] = average_scores_trend['dateAdded'].dt.to_timestamp()
average_scores_trend_fig = px.line(
    average_scores_trend,
    x='dateAdded',
    y=['EPSS', 'CVSS3'],
    title='Average EPSS and CVSS Scores Over Time',
    labels={'dateAdded': 'Date Added', 'value': 'Average Score'},
    line_shape='linear'
)
average_scores_trend_fig.update_layout(
    yaxis_title='Average Score',
    legend_title_text='Score Type'
)

# Severity Trend Over Time (Stacked Area Chart)
severity_trend = cisa_df.groupby([cisa_df['dateAdded'].dt.to_period('M'), 'Severity']).size().reset_index(name='Count')
severity_trend['dateAdded'] = severity_trend['dateAdded'].dt.to_timestamp()
severity_trend_fig = px.area(
    severity_trend,
    x='dateAdded',
    y='Count',
    color='Severity',
    title='Number of KEVs Added Over Time',
    labels={'dateAdded': 'Date Added', 'Count': 'Number of KEVs'},
    color_discrete_map=severity_colors
)

# * Impact Page *
# Top products by impact
product_impact = cisa_df.groupby('product').agg({'CVSS3': 'mean'}).reset_index().nlargest(10, 'CVSS3')
product_impact_bar = px.bar(
    product_impact, 
    x='product', 
    y='CVSS3', 
    title='Top Products by Impact', 
    labels={'product': 'Product', 'CVSS3': 'Average CVSS Base Score'},
    color_discrete_sequence=['rgb(1, 39, 67, 10)']
)

# Impact of CVEs with Known Ransomware Use
ransomware_impact = cisa_df.groupby('knownRansomwareCampaignUse').agg({'CVSS3': 'mean'}).reset_index()
ransomware_impact_bar = px.bar(
    ransomware_impact, 
    x='knownRansomwareCampaignUse', 
    y='CVSS3', 
    title='Impact of CVEs with Known Ransomware Use', 
    labels={'knownRansomwareCampaignUse': 'Known Ransomware Use', 'CVSS3': 'Average CVSS Base Score'},
    color_discrete_sequence=['rgb(1, 39, 67, 10)']
)

# Total Impact by Vendor
vendor_impact_paginated = cisa_df.groupby('vendorProject').agg({'CVSS3': 'sum'}).reset_index()
vendor_impact_paginated_fig = px.scatter(
    vendor_impact_paginated, 
    x='vendorProject', 
    y='CVSS3', 
    size='CVSS3', 
    title='Total Impact by Vendor', 
    labels={'vendorProject': 'Vendor/Project', 'CVSS3': 'Total CVSS Base Score'},
    color_discrete_sequence=['rgb(1, 39, 67, 10)']
)
vendor_impact_paginated_fig.update_layout(
    xaxis_tickangle=-45,
    height=600,
    margin=dict(l=20, r=20, t=40, b=150)
)

# Combined Risk vs. Vendor/Project
combined_risk_vendor_fig = px.bar(
    risk_by_vendor_df,
    x='vendorProject',
    y='CombinedRisk',
    title='Combined Risk by Vendor/Project',
    labels={'vendorProject': 'Vendor/Project', 'CombinedRisk': 'Average Combined Risk Score'},
    color_discrete_sequence=['rgb(1, 39, 67, 10)']
)

# Top Products by Combined Risk
top_products_combined_risk = cisa_df.groupby('product').agg({'CombinedRisk': 'mean'}).reset_index().nlargest(10, 'CombinedRisk')
top_products_combined_risk_fig = px.bar(
    top_products_combined_risk,
    x='product',
    y='CombinedRisk',
    title='Top Products by Combined Risk',
    labels={'product': 'Product', 'CombinedRisk': 'Average Combined Risk Score'},
    color_discrete_sequence=['rgb(1, 39, 67, 10)']
)

# * Risk Page *
# High-Risk CVEs by Vendor
high_risk_cves_paginated = cisa_df[cisa_df['CVSS3'] >= 7].groupby('vendorProject').size().reset_index(name='count')
high_risk_cves_paginated_fig = px.bar(
    high_risk_cves_paginated, 
    x='vendorProject', 
    y='count', 
    title='High-Risk CVEs by Vendor', 
    labels={'vendorProject': 'Vendor/Project', 'count': 'Number of High-Risk CVEs'},
    color_discrete_sequence=['rgb(1, 39, 67, 10)']
)
high_risk_cves_paginated_fig.update_layout(
    xaxis_tickangle=-45,
    height=600,
    margin=dict(l=20, r=20, t=40, b=150)
)

# High EPSS and High CVSS Scores
high_epss_cvss = cisa_df[(cisa_df['EPSS'] > 0.5) & (cisa_df['CVSS3'] > 7.0)]
high_epss_cvss_fig = px.scatter(
    high_epss_cvss,
    x='CVSS3',
    y='EPSS',
    title='High EPSS and High CVSS Scores',
    labels={'CVSS3': 'CVSS Base Score', 'EPSS': 'EPSS Score'},
    color='Severity',
    color_discrete_map=severity_colors,
    hover_data=['cveID', 'vulnerabilityName', 'vendorProject']
)

# Vendor/Project vs. Combined Risk
vendor_combined_risk = cisa_df.groupby('vendorProject').agg({'CombinedRisk': 'mean'}).reset_index()
vendor_combined_risk_fig = px.scatter(
    vendor_combined_risk,
    x='vendorProject',
    y='CombinedRisk',
    size='CombinedRisk',
    title='Vendor/Project vs. Combined Risk',
    labels={'vendorProject': 'Vendor/Project', 'CombinedRisk': 'Average Combined Risk Score'},
    color_discrete_sequence=['rgb(1, 39, 67, 10)']
)
vendor_combined_risk_fig.update_layout(
    xaxis_tickangle=-45,
    height=600,
    margin=dict(l=20, r=20, t=40, b=150)
)

# Top 5 Vendors with Highest Combined Risk Scores
top_5_vendors_combined_risk = risk_by_vendor_df.nlargest(5, 'CombinedRisk')
top_5_vendors_combined_risk_fig = px.bar(
    top_5_vendors_combined_risk,
    x='vendorProject',
    y='CombinedRisk',
    title='Top 5 Vendors with Highest Combined Risk Scores',
    labels={'vendorProject': 'Vendor/Project', 'CombinedRisk': 'Average Combined Risk Score'},
    color_discrete_sequence=['rgb(1, 39, 67, 10)']
)

# Remove any unnecessary columns from the data table
columns_to_remove = ["Highlight", "RiskLevel"]
existing_columns_to_remove = [col for col in columns_to_remove if col in cisa_df.columns]
if existing_columns_to_remove:
    cisa_df.drop(columns=existing_columns_to_remove, inplace=True)

# ====== Layouts ======
# Dashboard layout
dashboard_layout = html.Div([
    dbc.Container([
        html.H1("Summary Metrics", className="my-4"),
        dbc.Row([
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H5("Total KEVs", className="card-title"),
                    html.P(f"{total_kevs}", className="card-text")
                ])
            ], className="card-bordered graph-spacing"), width=3),
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H5("Average EPSS Score", className="card-title"),
                    html.P(f"{average_epss:.2f}", className="card-text")
                ])
            ], className="card-bordered"), width=3),
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H5("Average CVSS Score", className="card-title"),
                    html.P(f"{average_cvss:.2f}", className="card-text")
                ])
            ], className="card-bordered"), width=3),
        ], justify="center"),
        dbc.Row([
            dbc.Col(dcc.Graph(figure=severity_pie_fig, className="raisedbox graph-spacing"), width=6),
            dbc.Col(dcc.Graph(figure=top_vendors_fig, className="raisedbox graph-spacing"), width=6),
        ]),
        dbc.Row([
            dbc.Col(dcc.Graph(figure=severity_trend_fig, className="raisedbox graph-spacing"), width=12),
        ]),
        dbc.Row([
            dbc.Col(dcc.Graph(figure=severity_bar_fig, className="raisedbox"), width=12),
        ]),
    ])
])

# KEV Database layout
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

# STIR Page layout
def create_stir_page(title, graph1, graph2, table=None):
    elements = [
        dbc.Container([
            html.H1(title, className="my-4"),
            dcc.Graph(figure=graph1, className="raisedbox graph-spacing"),
            dcc.Graph(figure=graph2, className="raisedbox"),
        ])
    ]
    if table:
        elements.append(html.Div([html.H3("Top 10 Most Severe CVEs"), table]))
    return html.Div(elements)

severity_layout = html.Div([
    dbc.Container([
        html.H1("Severity", className="my-4"),
        dbc.Row([
            dbc.Col(html.Div(top_5_severe_kevs_table, className="raisedbox graph-spacing"), width=12)
        ]),
        dbc.Row([
            dbc.Col(dcc.Graph(figure=severity_by_vendor_paginated_fig, className="raisedbox graph-spacing"), width=12)
        ]),
        dbc.Row([
            dbc.Col(dcc.Graph(figure=severity_bar_fig, className="raisedbox graph-spacing"), width=12)
        ]),
        dbc.Row([
            dbc.Col(dcc.Graph(figure=scatter_fig, className="raisedbox graph-spacing"), width=12)
        ])
    ])
])

trends_layout = html.Div([
    dbc.Container([
        html.H1("Trends", className="my-4"),
        dcc.Graph(figure=severity_trend_fig, className="raisedbox graph-spacing"),
        dcc.Graph(figure=average_scores_trend_fig, className="raisedbox graph-spacing")
    ])
])

impact_layout = html.Div([
    dbc.Container([
        html.H1("Impact", className="my-4"),
        dcc.Graph(figure=product_impact_bar, className="raisedbox graph-spacing"),
        dcc.Graph(figure=top_products_combined_risk_fig, className="raisedbox graph-spacing"),
        dcc.Graph(figure=vendor_impact_paginated_fig, className="raisedbox graph-spacing"),
        dcc.Graph(figure=ransomware_impact_bar, className="raisedbox graph-spacing"),
        dcc.Graph(figure=combined_risk_vendor_fig, className="raisedbox graph-spacing")
    ])
])

risks_layout = html.Div([
    dbc.Container([
        html.H1("Risks", className="my-4"),
        dcc.Graph(figure=top_5_vendors_combined_risk_fig, className="raisedbox graph-spacing"),
        dcc.Graph(figure=vendor_combined_risk_fig, className="raisedbox graph-spacing"),
        dcc.Graph(figure=high_epss_cvss_fig, className="raisedbox graph-spacing"),
        dcc.Graph(figure=high_risk_cves_paginated_fig, className="raisedbox graph-spacing")   
    ])
])

# Define the app layout with a navigation bar
app.layout = html.Div([
    dbc.Navbar(
        dbc.Container([
            html.A(
                dbc.Row([
                    dbc.Col(html.Img(src="/assets/p1logo.png", height="80px")),
                    dbc.Col(dbc.NavbarBrand("Known Vulnerabilities Dashboard", className="ms-2 title-large")),
                ],
                align="center",
                className="g-0"
                ),
                href="/",
                style={"textDecoration": "none"}
            ),
            dbc.NavbarToggler(id="navbar-toggler"),
            dbc.Collapse(
                dbc.Nav(
                    [
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
                        ),
                    ],
                    className="ms-auto",
                    navbar=True
                ),
                id="navbar-collapse",
                navbar=True,
            ),
        ]),
        color="rgb(1, 39, 67, 10)",
        dark=True,
        expand="lg",
        className="mb-5 fixed-top"
    ),
    dcc.Location(id='url', refresh=False),
    html.Div(id='page-content', style={"color": "black", "paddingTop": "90px"})
])

# ====== Callbacks ======
# Page content
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

# KEV Database
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
    
    # ====== Adjustments ======
    # Rename columns
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
        "CVSS3": "CVSS",
        "CombinedRisk": "Combined Risk Score"
    }
    filtered_df = filtered_df.rename(columns=column_rename_dict)
    
    # Convert any non-supported types to strings
    filtered_df = convert_to_string(filtered_df)

    # Determine height based on the number of rows
    max_height = "500px"
    if len(filtered_df) <= 5:
        height = "auto"
    else:
        height = max_height
    
    # Create table with auto width adjustment
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
        style_data_conditional=[
            {
                'if': {'column_id': 'Description'},
                'whiteSpace': 'normal',
                'height': 'auto',
                'minWidth': '400px',
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
            },
            {
                'if': {'column_id': 'Vulnerability Name'},
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
        tooltip_duration=None,
        page_size=15
    )

if __name__ == '__main__':
    app.run_server(debug=True)
