﻿/*
Deployment script for FabrikamFiber

This code was generated by a tool.
Changes to this file may cause incorrect behavior and will be lost if
the code is regenerated.
*/

GO
SET ANSI_NULLS, ANSI_PADDING, ANSI_WARNINGS, ARITHABORT, CONCAT_NULL_YIELDS_NULL, QUOTED_IDENTIFIER ON;

SET NUMERIC_ROUNDABORT OFF;


GO
:setvar DatabaseName "FabrikamFiber"
:setvar DefaultFilePrefix "FabrikamFiber"
:setvar DefaultDataPath "D:\Program Files\Microsoft SQL Server\MSSQL12.MSSQLSERVER\MSSQL\DATA\"
:setvar DefaultLogPath "D:\Program Files\Microsoft SQL Server\MSSQL12.MSSQLSERVER\MSSQL\DATA\"

GO
:on error exit
GO
/*
Detect SQLCMD mode and disable script execution if SQLCMD mode is not supported.
To re-enable the script after enabling SQLCMD mode, execute the following:
SET NOEXEC OFF; 
*/
:setvar __IsSqlCmdEnabled "True"
GO
IF N'$(__IsSqlCmdEnabled)' NOT LIKE N'True'
    BEGIN
        PRINT N'SQLCMD mode must be enabled to successfully execute this script.';
        SET NOEXEC ON;
    END


GO
IF EXISTS (SELECT 1
           FROM   [master].[dbo].[sysdatabases]
           WHERE  [name] = N'$(DatabaseName)')
    BEGIN
        ALTER DATABASE [$(DatabaseName)]
            SET ANSI_NULLS ON,
                ANSI_PADDING ON,
                ANSI_WARNINGS ON,
                ARITHABORT ON,
                CONCAT_NULL_YIELDS_NULL ON,
                QUOTED_IDENTIFIER ON,
                ANSI_NULL_DEFAULT ON,
                CURSOR_DEFAULT LOCAL 
            WITH ROLLBACK IMMEDIATE;
    END


GO
IF EXISTS (SELECT 1
           FROM   [master].[dbo].[sysdatabases]
           WHERE  [name] = N'$(DatabaseName)')
    BEGIN
        ALTER DATABASE [$(DatabaseName)]
            SET PAGE_VERIFY NONE 
            WITH ROLLBACK IMMEDIATE;
    END


GO
USE [$(DatabaseName)];


GO
PRINT N'Rename refactoring operation with key 35545f1a-0182-4936-ad50-3ee64718e1e8 is skipped, element [dbo].[FK_ServiceTicket_Employee] (SqlForeignKeyConstraint) will not be renamed to [FK_ServiceTicket_CBEmployee]';


GO
PRINT N'Rename refactoring operation with key f6e85f57-ce5b-4a1b-94b3-0d97d78ef757 is skipped, element [dbo].[FK_ScheduleItem_ToTable] (SqlForeignKeyConstraint) will not be renamed to [FK_ScheduleItem_ServiceTicket]';


GO
PRINT N'Rename refactoring operation with key d5086424-61a0-48c9-b89e-deca4a34f18d, 90f822a0-956a-4de7-9f07-0e594a3c2866 is skipped, element [dbo].[ServiceTicket].[Desc] (SqlSimpleColumn) will not be renamed to Title';


GO
PRINT N'Rename refactoring operation with key 31e02f8d-8248-4ce5-b63f-3c224599f79c is skipped, element [dbo].[ServiceTicket].[CreatedBy] (SqlSimpleColumn) will not be renamed to CreatedById';


GO
PRINT N'Rename refactoring operation with key 47bc07fd-fb3c-4ecf-90ad-288d8e7ff4af is skipped, element [dbo].[FK_ServiceTicket_Employee] (SqlForeignKeyConstraint) will not be renamed to [FK_ServiceTicket_ATEmployee]';


GO
PRINT N'Creating [dbo].[Address]...';


GO
CREATE TABLE [dbo].[Address] (
    [Id]     INT           NOT NULL,
    [Street] NVARCHAR (50) NULL,
    [City]   NVARCHAR (50) NULL,
    [State]  NVARCHAR (50) NULL,
    [Zip]    NVARCHAR (10) NULL,
    PRIMARY KEY CLUSTERED ([Id] ASC)
);


GO
PRINT N'Creating [dbo].[Alert]...';


GO
CREATE TABLE [dbo].[Alert] (
    [Id]          INT            NOT NULL,
    [Created]     DATETIME       NOT NULL,
    [Description] NVARCHAR (100) NOT NULL,
    PRIMARY KEY CLUSTERED ([Id] ASC)
);


GO
PRINT N'Creating [dbo].[Customer]...';


GO
CREATE TABLE [dbo].[Customer] (
    [Id]        INT           NOT NULL,
    [FirstName] NVARCHAR (20) NOT NULL,
    [LastName]  NVARCHAR (20) NOT NULL,
    [AddressId] INT           NOT NULL,
    PRIMARY KEY CLUSTERED ([Id] ASC)
);


GO
PRINT N'Creating [dbo].[Employee]...';


GO
CREATE TABLE [dbo].[Employee] (
    [Id]           INT            NOT NULL,
    [FirstName]    NVARCHAR (20)  NOT NULL,
    [LastName]     NVARCHAR (20)  NOT NULL,
    [AddressId]    INT            NOT NULL,
    [Identity]     NVARCHAR (50)  NOT NULL,
    [ServiceAreas] NVARCHAR (150) NULL,
    PRIMARY KEY CLUSTERED ([Id] ASC)
);


GO
PRINT N'Creating [dbo].[Message]...';


GO
CREATE TABLE [dbo].[Message] (
    [Id]          INT            NOT NULL,
    [Sent]        DATETIME       NOT NULL,
    [Description] NVARCHAR (300) NOT NULL,
    PRIMARY KEY CLUSTERED ([Id] ASC)
);


GO
PRINT N'Creating [dbo].[Phone]...';


GO
CREATE TABLE [dbo].[Phone] (
    [Id]         INT           NOT NULL,
    [Label]      NVARCHAR (50) NULL,
    [Number]     NVARCHAR (20) NOT NULL,
    [CustomerId] INT           NULL,
    [EmployeeId] INT           NULL,
    PRIMARY KEY CLUSTERED ([Id] ASC)
);


GO
PRINT N'Creating [dbo].[ScheduleItem]...';


GO
CREATE TABLE [dbo].[ScheduleItem] (
    [Id]              INT      NOT NULL,
    [EmployeeId]      INT      NULL,
    [ServiceTicketId] INT      NULL,
    [Start]           DATETIME NOT NULL,
    [WorkHours]       INT      NOT NULL,
    [AssignedOn]      DATETIME NOT NULL,
    PRIMARY KEY CLUSTERED ([Id] ASC)
);


GO
PRINT N'Creating [dbo].[ServiceLogEntry]...';


GO
CREATE TABLE [dbo].[ServiceLogEntry] (
    [Id]              INT            NOT NULL,
    [CreatedAt]       DATETIME       NOT NULL,
    [Description]     NVARCHAR (300) NOT NULL,
    [CreatedById]     INT            NOT NULL,
    [ServiceTicketId] INT            NOT NULL,
    PRIMARY KEY CLUSTERED ([Id] ASC)
);


GO
PRINT N'Creating [dbo].[ServiceTicket]...';


GO
CREATE TABLE [dbo].[ServiceTicket] (
    [Id]              INT            NOT NULL,
    [Title]           NVARCHAR (50)  NOT NULL,
    [Description]     NVARCHAR (300) NOT NULL,
    [StatusId]        INT            NOT NULL,
    [StatusValue]     INT            NOT NULL,
    [EscalationLevel] INT            NOT NULL,
    [Opened]          DATETIME       NULL,
    [Closed]          DATETIME       NULL,
    [CustomerId]      INT            NULL,
    [CreatedById]     INT            NULL,
    [AssignedToId]    INT            NULL,
    [TimeOpen]        NVARCHAR (20)  NOT NULL,
    PRIMARY KEY CLUSTERED ([Id] ASC)
);


GO
PRINT N'Creating [dbo].[Status]...';


GO
CREATE TABLE [dbo].[Status] (
    [Id]          INT           NOT NULL,
    [Description] NVARCHAR (20) NOT NULL,
    PRIMARY KEY CLUSTERED ([Id] ASC)
);


GO
PRINT N'Creating [dbo].[FK_Customer_Address]...';


GO
ALTER TABLE [dbo].[Customer] WITH NOCHECK
    ADD CONSTRAINT [FK_Customer_Address] FOREIGN KEY ([AddressId]) REFERENCES [dbo].[Address] ([Id]);


GO
PRINT N'Creating [dbo].[FK_Employee_Address]...';


GO
ALTER TABLE [dbo].[Employee] WITH NOCHECK
    ADD CONSTRAINT [FK_Employee_Address] FOREIGN KEY ([AddressId]) REFERENCES [dbo].[Address] ([Id]);


GO
PRINT N'Creating [dbo].[FK_Phone_Customer]...';


GO
ALTER TABLE [dbo].[Phone] WITH NOCHECK
    ADD CONSTRAINT [FK_Phone_Customer] FOREIGN KEY ([CustomerId]) REFERENCES [dbo].[Customer] ([Id]);


GO
PRINT N'Creating [dbo].[FK_Phone_Employee]...';


GO
ALTER TABLE [dbo].[Phone] WITH NOCHECK
    ADD CONSTRAINT [FK_Phone_Employee] FOREIGN KEY ([EmployeeId]) REFERENCES [dbo].[Employee] ([Id]);


GO
PRINT N'Creating [dbo].[FK_ScheduleItem_Employee]...';


GO
ALTER TABLE [dbo].[ScheduleItem] WITH NOCHECK
    ADD CONSTRAINT [FK_ScheduleItem_Employee] FOREIGN KEY ([EmployeeId]) REFERENCES [dbo].[Employee] ([Id]);


GO
PRINT N'Creating [dbo].[FK_ScheduleItem_ServiceTicket]...';


GO
ALTER TABLE [dbo].[ScheduleItem] WITH NOCHECK
    ADD CONSTRAINT [FK_ScheduleItem_ServiceTicket] FOREIGN KEY ([ServiceTicketId]) REFERENCES [dbo].[ServiceTicket] ([Id]);


GO
PRINT N'Creating [dbo].[FK_ServiceLogEntry_Employee]...';


GO
ALTER TABLE [dbo].[ServiceLogEntry] WITH NOCHECK
    ADD CONSTRAINT [FK_ServiceLogEntry_Employee] FOREIGN KEY ([CreatedById]) REFERENCES [dbo].[Employee] ([Id]);


GO
PRINT N'Creating [dbo].[FK_ServiceLogEntry_ServiceTicket]...';


GO
ALTER TABLE [dbo].[ServiceLogEntry] WITH NOCHECK
    ADD CONSTRAINT [FK_ServiceLogEntry_ServiceTicket] FOREIGN KEY ([ServiceTicketId]) REFERENCES [dbo].[ServiceTicket] ([Id]);


GO
PRINT N'Creating [dbo].[FK_ServiceTicket_Status]...';


GO
ALTER TABLE [dbo].[ServiceTicket] WITH NOCHECK
    ADD CONSTRAINT [FK_ServiceTicket_Status] FOREIGN KEY ([StatusId]) REFERENCES [dbo].[Status] ([Id]);


GO
PRINT N'Creating [dbo].[FK_ServiceTicket_Customer]...';


GO
ALTER TABLE [dbo].[ServiceTicket] WITH NOCHECK
    ADD CONSTRAINT [FK_ServiceTicket_Customer] FOREIGN KEY ([CustomerId]) REFERENCES [dbo].[Customer] ([Id]);


GO
PRINT N'Creating [dbo].[FK_ServiceTicket_CBEmployee]...';


GO
ALTER TABLE [dbo].[ServiceTicket] WITH NOCHECK
    ADD CONSTRAINT [FK_ServiceTicket_CBEmployee] FOREIGN KEY ([CreatedById]) REFERENCES [dbo].[Employee] ([Id]);


GO
PRINT N'Creating [dbo].[FK_ServiceTicket_ATEmployee]...';


GO
ALTER TABLE [dbo].[ServiceTicket] WITH NOCHECK
    ADD CONSTRAINT [FK_ServiceTicket_ATEmployee] FOREIGN KEY ([AssignedToId]) REFERENCES [dbo].[Employee] ([Id]);


GO
-- Refactoring step to update target server with deployed transaction logs

IF OBJECT_ID(N'dbo.__RefactorLog') IS NULL
BEGIN
    CREATE TABLE [dbo].[__RefactorLog] (OperationKey UNIQUEIDENTIFIER NOT NULL PRIMARY KEY)
    EXEC sp_addextendedproperty N'microsoft_database_tools_support', N'refactoring log', N'schema', N'dbo', N'table', N'__RefactorLog'
END
GO
IF NOT EXISTS (SELECT OperationKey FROM [dbo].[__RefactorLog] WHERE OperationKey = 'f6e85f57-ce5b-4a1b-94b3-0d97d78ef757')
INSERT INTO [dbo].[__RefactorLog] (OperationKey) values ('f6e85f57-ce5b-4a1b-94b3-0d97d78ef757')
IF NOT EXISTS (SELECT OperationKey FROM [dbo].[__RefactorLog] WHERE OperationKey = 'd5086424-61a0-48c9-b89e-deca4a34f18d')
INSERT INTO [dbo].[__RefactorLog] (OperationKey) values ('d5086424-61a0-48c9-b89e-deca4a34f18d')
IF NOT EXISTS (SELECT OperationKey FROM [dbo].[__RefactorLog] WHERE OperationKey = '90f822a0-956a-4de7-9f07-0e594a3c2866')
INSERT INTO [dbo].[__RefactorLog] (OperationKey) values ('90f822a0-956a-4de7-9f07-0e594a3c2866')
IF NOT EXISTS (SELECT OperationKey FROM [dbo].[__RefactorLog] WHERE OperationKey = '31e02f8d-8248-4ce5-b63f-3c224599f79c')
INSERT INTO [dbo].[__RefactorLog] (OperationKey) values ('31e02f8d-8248-4ce5-b63f-3c224599f79c')
IF NOT EXISTS (SELECT OperationKey FROM [dbo].[__RefactorLog] WHERE OperationKey = '35545f1a-0182-4936-ad50-3ee64718e1e8')
INSERT INTO [dbo].[__RefactorLog] (OperationKey) values ('35545f1a-0182-4936-ad50-3ee64718e1e8')
IF NOT EXISTS (SELECT OperationKey FROM [dbo].[__RefactorLog] WHERE OperationKey = '47bc07fd-fb3c-4ecf-90ad-288d8e7ff4af')
INSERT INTO [dbo].[__RefactorLog] (OperationKey) values ('47bc07fd-fb3c-4ecf-90ad-288d8e7ff4af')

GO

GO
PRINT N'Checking existing data against newly created constraints';


GO
USE [$(DatabaseName)];


GO
ALTER TABLE [dbo].[Customer] WITH CHECK CHECK CONSTRAINT [FK_Customer_Address];

ALTER TABLE [dbo].[Employee] WITH CHECK CHECK CONSTRAINT [FK_Employee_Address];

ALTER TABLE [dbo].[Phone] WITH CHECK CHECK CONSTRAINT [FK_Phone_Customer];

ALTER TABLE [dbo].[Phone] WITH CHECK CHECK CONSTRAINT [FK_Phone_Employee];

ALTER TABLE [dbo].[ScheduleItem] WITH CHECK CHECK CONSTRAINT [FK_ScheduleItem_Employee];

ALTER TABLE [dbo].[ScheduleItem] WITH CHECK CHECK CONSTRAINT [FK_ScheduleItem_ServiceTicket];

ALTER TABLE [dbo].[ServiceLogEntry] WITH CHECK CHECK CONSTRAINT [FK_ServiceLogEntry_Employee];

ALTER TABLE [dbo].[ServiceLogEntry] WITH CHECK CHECK CONSTRAINT [FK_ServiceLogEntry_ServiceTicket];

ALTER TABLE [dbo].[ServiceTicket] WITH CHECK CHECK CONSTRAINT [FK_ServiceTicket_Status];

ALTER TABLE [dbo].[ServiceTicket] WITH CHECK CHECK CONSTRAINT [FK_ServiceTicket_Customer];

ALTER TABLE [dbo].[ServiceTicket] WITH CHECK CHECK CONSTRAINT [FK_ServiceTicket_CBEmployee];

ALTER TABLE [dbo].[ServiceTicket] WITH CHECK CHECK CONSTRAINT [FK_ServiceTicket_ATEmployee];


GO
PRINT N'Update complete.';


GO
