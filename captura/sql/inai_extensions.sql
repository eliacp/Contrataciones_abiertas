
/***
 * RequestForQuotes
 ***/

drop table if exists RequestForQuotes cascade;
create table RequestForQuotes(
id serial primary key
title text,
description text,
period_startdate timestamp,
period_enddate timestamp,
);

drop table if exists RequestForQuotesItems cascade;
create table RequestForQuotesItems(
id serial primary key,
requestforquotes_id integer references RequestForQuotes(id) on delete cascade,

	contractingprocess_id int references ContractingProcess(id) on delete cascade,
	tender_id int references Tender(id) on delete cascade,
	itemid text,
	description text,
	classification_scheme text,
    classification_id text,
    classification_description text,
    classification_uri text,
	quantity int,
	unit_name text,
	unit_value_amount decimal,
	unit_value_currency text

);

drop table ir exists RequestForQuotesPossibleSuppliers cascade;
create table RequestForQuotesPossibleSuppliers(
id serial primary key,
requestforquotes_id integer references RequestForQuotes(id) on delete cascade,
parties_id integer references Parties(id)
);

drop table Quotes cascade;
create table Quotes(
id serial primary key,
requestforquotes_id integer references RequestForQuotes(id) on delete cascade
description
date timestamp,
/* items */
value_amount decimal,
value_currency text,
qoutePeriod_startdate timestamp,
quotePeriod_enddate timestamp,
issuingSupplier_id integer references Parties(id), /* id, name */
/* invitedSuppliers */
);

drop table QuotesItems cascade;
create table QuotesItems(
id serial primary key,
quotes_id integer references Quotes(id) on delete cascade,

	contractingprocess_id int references ContractingProcess(id) on delete cascade,
	tender_id int references Tender(id) on delete cascade,
	itemid text,
	description text,
	classification_scheme text,
    classification_id text,
    classification_description text,
    classification_uri text,
	quantity int,
	unit_name text,
	unit_value_amount decimal,
	unit_value_currency text


);

drop table InvitedSuppliers cascade;
create table InvitedSuppliers(
id serial primary key,
quotes_id integer references Quotes(id) on delete cascade,
parties_id integer references Parties(id) on delete cascade
);

/***
 * ClarificationMeetings
 ***/

drop table ClarificationMeeting cascade;
create table ClarificationMeeting(
id serial primary key,
date timestamp
);

create table ClarificationMeetingAttendees(
id serial primary key,
clarificationmeeting_id integer references ClarificationMeeting(id) on delete cascade,
parties_id integer references Parties(id)
);

create table ClarificationMeetingOfficials(
id serial primary key,
clarificationmeeting_id integer references ClarificationMeeting(id) on delete cascade,
parties_id integer references Parties(id)
);

