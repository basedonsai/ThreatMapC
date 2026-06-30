IF OBJECT_ID('dbo.Threats', 'U') IS NOT NULL DROP TABLE dbo.Threats;
IF OBJECT_ID('dbo.Zones',   'U') IS NOT NULL DROP TABLE dbo.Zones;
IF OBJECT_ID('dbo.Plots',   'U') IS NOT NULL DROP TABLE dbo.Plots;
GO

CREATE TABLE Plots (
    PlotId       NVARCHAR(64)  NOT NULL PRIMARY KEY,
    PlotName     NVARCHAR(255) NOT NULL,

    -- New columns for single-layout architecture
    DisplayName  NVARCHAR(256) NULL,
    ImagePath    NVARCHAR(500) NULL,
    ImageHash    NVARCHAR(128) NULL,
    IsActive     BIT           NOT NULL DEFAULT 0,

    -- Existing columns
    IsPublished  BIT           NOT NULL DEFAULT 0,
    CreatedAt    DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(),
    PublishedAt  DATETIME2     NULL
);
GO

CREATE TABLE Zones (
    ZoneId        INT IDENTITY(1,1) PRIMARY KEY,
    PlotId        NVARCHAR(64)  NOT NULL,
    UnitId        NVARCHAR(64)  NOT NULL,
    Shape         NVARCHAR(20)  NOT NULL,
    GeometryJson  NVARCHAR(MAX) NOT NULL,
    DisplayOrder  INT           NOT NULL DEFAULT 0,
    CONSTRAINT FK_Zones_Plots FOREIGN KEY (PlotId)
        REFERENCES Plots(PlotId) ON DELETE CASCADE
);
GO

CREATE INDEX IX_Zones_PlotId ON Zones(PlotId);
GO

CREATE UNIQUE INDEX UX_Plots_OneActive
ON Plots(IsActive)
WHERE IsActive = 1;

CREATE TABLE Threats (
    PlotId        NVARCHAR(64)  NOT NULL,
    UnitId        NVARCHAR(64)  NOT NULL,
    Score         FLOAT         NULL,
    ShortTerm     FLOAT         NULL,
    LongTerm      FLOAT         NULL,
    Status        NVARCHAR(50)  NULL,
    ThreatLevel   NVARCHAR(50)  NULL,
    CONSTRAINT PK_Threats PRIMARY KEY (PlotId, UnitId),
    CONSTRAINT FK_Threats_Plots FOREIGN KEY (PlotId)
        REFERENCES Plots(PlotId) ON DELETE CASCADE
);
GO